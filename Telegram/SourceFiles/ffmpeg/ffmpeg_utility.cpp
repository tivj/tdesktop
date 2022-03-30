/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "ffmpeg/ffmpeg_utility.h"

#include "base/algorithm.h"
#include "logs.h"

#include <QImage>

#ifdef LIB_FFMPEG_USE_QT_PRIVATE_API
#include <private/qdrawhelper_p.h>
#endif // LIB_FFMPEG_USE_QT_PRIVATE_API

extern "C" {
#include <libavutil/opt.h>
} // extern "C"

namespace FFmpeg {
namespace {

// See https://github.com/telegramdesktop/tdesktop/issues/7225
constexpr auto kAlignImageBy = 64;
constexpr auto kImageFormat = QImage::Format_ARGB32_Premultiplied;
constexpr auto kMaxScaleByAspectRatio = 16;
constexpr auto kAvioBlockSize = 4096;
constexpr auto kTimeUnknown = std::numeric_limits<crl::time>::min();
constexpr auto kDurationMax = crl::time(std::numeric_limits<int>::max());

using GetFormatMethod = enum AVPixelFormat(*)(
	struct AVCodecContext *s,
	const enum AVPixelFormat *fmt);

struct HwAccelDescriptor {
	GetFormatMethod getFormat = nullptr;
	AVPixelFormat format = AV_PIX_FMT_NONE;
};

void AlignedImageBufferCleanupHandler(void* data) {
	const auto buffer = static_cast<uchar*>(data);
	delete[] buffer;
}

[[nodiscard]] bool IsValidAspectRatio(AVRational aspect) {
	return (aspect.num > 0)
		&& (aspect.den > 0)
		&& (aspect.num <= aspect.den * kMaxScaleByAspectRatio)
		&& (aspect.den <= aspect.num * kMaxScaleByAspectRatio);
}

[[nodiscard]] bool IsAlignedImage(const QImage &image) {
	return !(reinterpret_cast<uintptr_t>(image.bits()) % kAlignImageBy)
		&& !(image.bytesPerLine() % kAlignImageBy);
}

void UnPremultiplyLine(uchar *dst, const uchar *src, int intsCount) {
	[[maybe_unused]] const auto udst = reinterpret_cast<uint*>(dst);
	const auto usrc = reinterpret_cast<const uint*>(src);

#ifndef LIB_FFMPEG_USE_QT_PRIVATE_API
	for (auto i = 0; i != intsCount; ++i) {
		udst[i] = qUnpremultiply(usrc[i]);
	}
#else // !LIB_FFMPEG_USE_QT_PRIVATE_API
	static const auto layout = &qPixelLayouts[QImage::Format_ARGB32];
	layout->storeFromARGB32PM(dst, usrc, 0, intsCount, nullptr, nullptr);
#endif // LIB_FFMPEG_USE_QT_PRIVATE_API
}

void PremultiplyLine(uchar *dst, const uchar *src, int intsCount) {
	const auto udst = reinterpret_cast<uint*>(dst);
	[[maybe_unused]] const auto usrc = reinterpret_cast<const uint*>(src);

#ifndef LIB_FFMPEG_USE_QT_PRIVATE_API
	for (auto i = 0; i != intsCount; ++i) {
		udst[i] = qPremultiply(usrc[i]);
	}
#else // !LIB_FFMPEG_USE_QT_PRIVATE_API
	static const auto layout = &qPixelLayouts[QImage::Format_ARGB32];
	layout->fetchToARGB32PM(udst, src, 0, intsCount, nullptr, nullptr);
#endif // LIB_FFMPEG_USE_QT_PRIVATE_API
}

[[nodiscard]] bool InitHw(AVCodecContext *context, AVHWDeviceType type) {
	auto hwDeviceContext = (AVBufferRef*)nullptr;
	AvErrorWrap error = av_hwdevice_ctx_create(
		&hwDeviceContext,
		type,
		nullptr,
		nullptr,
		0);
	if (error || !hwDeviceContext) {
		LogError(qstr("av_hwdevice_ctx_create"), error);
		return false;
	}
	DEBUG_LOG(("Video Info: "
		"Trying \"%1\" hardware acceleration for \"%2\" decoder."
		).arg(av_hwdevice_get_type_name(type)
		).arg(context->codec->name));
	if (context->hw_device_ctx) {
		av_buffer_unref(&context->hw_device_ctx);
	}
	context->hw_device_ctx = av_buffer_ref(hwDeviceContext);
	av_buffer_unref(&hwDeviceContext);
	return true;
}

[[nodiscard]] enum AVPixelFormat GetHwFormat(
		AVCodecContext *context,
		const enum AVPixelFormat *formats) {
	const auto has = [&](enum AVPixelFormat format) {
		const enum AVPixelFormat *p = nullptr;
		for (p = formats; *p != AV_PIX_FMT_NONE; p++) {
			if (*p == format) {
				return true;
			}
		}
		return false;
	};
	const auto list = std::array{
#ifdef Q_OS_WIN
		AV_PIX_FMT_D3D11,
		AV_PIX_FMT_DXVA2_VLD,
		AV_PIX_FMT_CUDA,
#elif defined Q_OS_MAC // Q_OS_WIN
		AV_PIX_FMT_VIDEOTOOLBOX,
#else // Q_OS_WIN || Q_OS_MAC
		AV_PIX_FMT_VAAPI,
		AV_PIX_FMT_VDPAU,
		AV_PIX_FMT_CUDA,
#endif // Q_OS_WIN || Q_OS_MAC
	};
	for (const auto format : list) {
		if (!has(format)) {
			continue;
		}
		const auto type = [&] {
			switch (format) {
#ifdef Q_OS_WIN
			case AV_PIX_FMT_D3D11: return AV_HWDEVICE_TYPE_D3D11VA;
			case AV_PIX_FMT_DXVA2_VLD: return AV_HWDEVICE_TYPE_DXVA2;
			case AV_PIX_FMT_CUDA: return AV_HWDEVICE_TYPE_CUDA;
#elif defined Q_OS_MAC // Q_OS_WIN
			case AV_PIX_FMT_VIDEOTOOLBOX:
				return AV_HWDEVICE_TYPE_VIDEOTOOLBOX;
#else // Q_OS_WIN || Q_OS_MAC
			case AV_PIX_FMT_VAAPI: return AV_HWDEVICE_TYPE_VAAPI;
			case AV_PIX_FMT_VDPAU: return AV_HWDEVICE_TYPE_VDPAU;
#endif // Q_OS_WIN || Q_OS_MAC
			}
			return AV_HWDEVICE_TYPE_NONE;
		}();
		if (type == AV_HWDEVICE_TYPE_NONE && context->hw_device_ctx) {
			av_buffer_unref(&context->hw_device_ctx);
		} else if (type != AV_HWDEVICE_TYPE_NONE && !InitHw(context, type)) {
			continue;
		}
		return format;
	}
	enum AVPixelFormat result = AV_PIX_FMT_NONE;
	for (const enum AVPixelFormat *p = formats; *p != AV_PIX_FMT_NONE; p++) {
		result = *p;
	}
	return result;
}

template <AVPixelFormat Required>
enum AVPixelFormat GetFormatImplementation(
		AVCodecContext *ctx,
		const enum AVPixelFormat *pix_fmts) {
	const enum AVPixelFormat *p = nullptr;
	for (p = pix_fmts; *p != -1; p++) {
		if (*p == Required) {
			return *p;
		}
	}
	return AV_PIX_FMT_NONE;
}

template <AVPixelFormat Format>
[[nodiscard]] HwAccelDescriptor HwAccelByFormat() {
	return {
		.getFormat = GetFormatImplementation<Format>,
		.format = Format,
	};
}

[[nodiscard]] HwAccelDescriptor ResolveHwAccel(
		not_null<const AVCodec*> decoder,
		AVHWDeviceType type) {
	Expects(type != AV_HWDEVICE_TYPE_NONE);

	const auto format = [&] {
		for (auto i = 0;; i++) {
			const auto config = avcodec_get_hw_config(decoder, i);
			if (!config) {
				break;
			} else if (config->device_type == type
				&& (config->methods
					& AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX)) {
				return config->pix_fmt;
			}
		}
		return AV_PIX_FMT_NONE;
	}();

	switch (format) {
#ifdef Q_OS_WIN
	case AV_PIX_FMT_D3D11:
		return HwAccelByFormat<AV_PIX_FMT_D3D11>();
	case AV_PIX_FMT_DXVA2_VLD:
		return HwAccelByFormat<AV_PIX_FMT_DXVA2_VLD>();
	case AV_PIX_FMT_D3D11VA_VLD:
		return HwAccelByFormat<AV_PIX_FMT_D3D11VA_VLD>();
#elif defined Q_OS_MAC // Q_OS_WIN
	case AV_PIX_FMT_VIDEOTOOLBOX:
		return HwAccelByFormat<AV_PIX_FMT_VIDEOTOOLBOX>();
#else // Q_OS_WIN || Q_OS_MAC
	case AV_PIX_FMT_VAAPI:
		return HwAccelByFormat<AV_PIX_FMT_VAAPI>();
	case AV_PIX_FMT_VDPAU:
		return HwAccelByFormat<AV_PIX_FMT_VDPAU>();
#endif // Q_OS_WIN || Q_OS_MAC
	case AV_PIX_FMT_CUDA:
		return HwAccelByFormat<AV_PIX_FMT_CUDA>();
	}
	return {};
}

} // namespace

IOPointer MakeIOPointer(
		void *opaque,
		int(*read)(void *opaque, uint8_t *buffer, int bufferSize),
		int(*write)(void *opaque, uint8_t *buffer, int bufferSize),
		int64_t(*seek)(void *opaque, int64_t offset, int whence)) {
	auto buffer = reinterpret_cast<uchar*>(av_malloc(kAvioBlockSize));
	if (!buffer) {
		LogError(qstr("av_malloc"));
		return {};
	}
	auto result = IOPointer(avio_alloc_context(
		buffer,
		kAvioBlockSize,
		write ? 1 : 0,
		opaque,
		read,
		write,
		seek));
	if (!result) {
		av_freep(&buffer);
		LogError(qstr("avio_alloc_context"));
		return {};
	}
	return result;
}

void IODeleter::operator()(AVIOContext *value) {
	if (value) {
		av_freep(&value->buffer);
		avio_context_free(&value);
	}
}

FormatPointer MakeFormatPointer(
		void *opaque,
		int(*read)(void *opaque, uint8_t *buffer, int bufferSize),
		int(*write)(void *opaque, uint8_t *buffer, int bufferSize),
		int64_t(*seek)(void *opaque, int64_t offset, int whence)) {
	auto io = MakeIOPointer(opaque, read, write, seek);
	if (!io) {
		return {};
	}
	auto result = avformat_alloc_context();
	if (!result) {
		LogError(qstr("avformat_alloc_context"));
		return {};
	}
	result->pb = io.get();

	auto options = (AVDictionary*)nullptr;
	const auto guard = gsl::finally([&] { av_dict_free(&options); });
	av_dict_set(&options, "usetoc", "1", 0);
	const auto error = AvErrorWrap(avformat_open_input(
		&result,
		nullptr,
		nullptr,
		&options));
	if (error) {
		// avformat_open_input freed 'result' in case an error happened.
		LogError(qstr("avformat_open_input"), error);
		return {};
	}
	result->flags |= AVFMT_FLAG_FAST_SEEK;

	// Now FormatPointer will own and free the IO context.
	io.release();
	return FormatPointer(result);
}

void FormatDeleter::operator()(AVFormatContext *value) {
	if (value) {
		const auto deleter = IOPointer(value->pb);
		avformat_close_input(&value);
	}
}

const AVCodec *FindDecoder(not_null<AVCodecContext*> context) {
	// Force libvpx-vp9, because we need alpha channel support.
	return (context->codec_id == AV_CODEC_ID_VP9)
		? avcodec_find_decoder_by_name("libvpx-vp9")
		: avcodec_find_decoder(context->codec_id);
}

CodecPointer MakeCodecPointer(CodecDescriptor descriptor) {
	auto error = AvErrorWrap();

	auto result = CodecPointer(avcodec_alloc_context3(nullptr));
	const auto context = result.get();
	if (!context) {
		LogError(qstr("avcodec_alloc_context3"));
		return {};
	}
	const auto stream = descriptor.stream;
	error = avcodec_parameters_to_context(context, stream->codecpar);
	if (error) {
		LogError(qstr("avcodec_parameters_to_context"), error);
		return {};
	}
	context->pkt_timebase = stream->time_base;
	av_opt_set(context, "threads", "auto", 0);
	av_opt_set_int(context, "refcounted_frames", 1, 0);

	const auto codec = FindDecoder(context);
	if (!codec) {
		LogError(qstr("avcodec_find_decoder"), context->codec_id);
		return {};
	}

	if (descriptor.hwAllowed) {
		context->get_format = GetHwFormat;
	} else {
		DEBUG_LOG(("Video Info: Using software \"%2\" decoder."
			).arg(codec->name));
	}

	if ((error = avcodec_open2(context, codec, nullptr))) {
		LogError(qstr("avcodec_open2"), error);
		return {};
	}
	return result;
}

void CodecDeleter::operator()(AVCodecContext *value) {
	if (value) {
		avcodec_free_context(&value);
	}
}

FramePointer MakeFramePointer() {
	return FramePointer(av_frame_alloc());
}

bool FrameHasData(AVFrame *frame) {
	return (frame && frame->data[0] != nullptr);
}

void ClearFrameMemory(AVFrame *frame) {
	if (FrameHasData(frame)) {
		av_frame_unref(frame);
	}
}

void FrameDeleter::operator()(AVFrame *value) {
	av_frame_free(&value);
}

SwscalePointer MakeSwscalePointer(
		QSize srcSize,
		int srcFormat,
		QSize dstSize,
		int dstFormat,
		SwscalePointer *existing) {
	// We have to use custom caching for SwsContext, because
	// sws_getCachedContext checks passed flags with existing context flags,
	// and re-creates context if they're different, but in the process of
	// context creation the passed flags are modified before being written
	// to the resulting context, so the caching doesn't work.
	if (existing && (*existing) != nullptr) {
		const auto &deleter = existing->get_deleter();
		if (deleter.srcSize == srcSize
			&& deleter.srcFormat == srcFormat
			&& deleter.dstSize == dstSize
			&& deleter.dstFormat == dstFormat) {
			return std::move(*existing);
		}
	}
	if (srcFormat <= AV_PIX_FMT_NONE || srcFormat >= AV_PIX_FMT_NB) {
		LogError(qstr("frame->format"));
		return SwscalePointer();
	}

	const auto result = sws_getCachedContext(
		existing ? existing->release() : nullptr,
		srcSize.width(),
		srcSize.height(),
		AVPixelFormat(srcFormat),
		dstSize.width(),
		dstSize.height(),
		AVPixelFormat(dstFormat),
		0,
		nullptr,
		nullptr,
		nullptr);
	if (!result) {
		LogError(qstr("sws_getCachedContext"));
	}
	return SwscalePointer(
		result,
		{ srcSize, srcFormat, dstSize, dstFormat });
}

SwscalePointer MakeSwscalePointer(
		not_null<AVFrame*> frame,
		QSize resize,
		SwscalePointer *existing) {
	return MakeSwscalePointer(
		QSize(frame->width, frame->height),
		frame->format,
		resize,
		AV_PIX_FMT_BGRA,
		existing);
}

void SwscaleDeleter::operator()(SwsContext *value) {
	if (value) {
		sws_freeContext(value);
	}
}

void LogError(QLatin1String method) {
	LOG(("Streaming Error: Error in %1.").arg(method));
}

void LogError(QLatin1String method, AvErrorWrap error) {
	LOG(("Streaming Error: Error in %1 (code: %2, text: %3)."
		).arg(method
		).arg(error.code()
		).arg(error.text()));
}

crl::time PtsToTime(int64_t pts, AVRational timeBase) {
	return (pts == AV_NOPTS_VALUE || !timeBase.den)
		? kTimeUnknown
		: ((pts * 1000LL * timeBase.num) / timeBase.den);
}

crl::time PtsToTimeCeil(int64_t pts, AVRational timeBase) {
	return (pts == AV_NOPTS_VALUE || !timeBase.den)
		? kTimeUnknown
		: ((pts * 1000LL * timeBase.num + timeBase.den - 1) / timeBase.den);
}

int64_t TimeToPts(crl::time time, AVRational timeBase) {
	return (time == kTimeUnknown || !timeBase.num)
		? AV_NOPTS_VALUE
		: (time * timeBase.den) / (1000LL * timeBase.num);
}

crl::time PacketPosition(const Packet &packet, AVRational timeBase) {
	const auto &native = packet.fields();
	return PtsToTime(
		(native.pts == AV_NOPTS_VALUE) ? native.dts : native.pts,
		timeBase);
}

crl::time PacketDuration(const Packet &packet, AVRational timeBase) {
	return PtsToTime(packet.fields().duration, timeBase);
}

int DurationByPacket(const Packet &packet, AVRational timeBase) {
	const auto position = PacketPosition(packet, timeBase);
	const auto duration = std::max(
		PacketDuration(packet, timeBase),
		crl::time(1));
	const auto bad = [](crl::time time) {
		return (time < 0) || (time > kDurationMax);
	};
	if (bad(position) || bad(duration) || bad(position + duration + 1)) {
		LOG(("Streaming Error: Wrong duration by packet: %1 + %2"
			).arg(position
			).arg(duration));
		return -1;
	}
	return int(position + duration + 1);
}

int ReadRotationFromMetadata(not_null<AVStream*> stream) {
	const auto tag = av_dict_get(stream->metadata, "rotate", nullptr, 0);
	if (tag && *tag->value) {
		const auto string = QString::fromUtf8(tag->value);
		auto ok = false;
		const auto degrees = string.toInt(&ok);
		if (ok && (degrees == 90 || degrees == 180 || degrees == 270)) {
			return degrees;
		}
	}
	return 0;
}

AVRational ValidateAspectRatio(AVRational aspect) {
	return IsValidAspectRatio(aspect) ? aspect : kNormalAspect;
}

QSize CorrectByAspect(QSize size, AVRational aspect) {
	Expects(IsValidAspectRatio(aspect));

	return QSize(size.width() * aspect.num / aspect.den, size.height());
}

bool RotationSwapWidthHeight(int rotation) {
	return (rotation == 90 || rotation == 270);
}

bool GoodStorageForFrame(const QImage &storage, QSize size) {
	return !storage.isNull()
		&& (storage.format() == kImageFormat)
		&& (storage.size() == size)
		&& storage.isDetached()
		&& IsAlignedImage(storage);
}

// Create a QImage of desired size where all the data is properly aligned.
QImage CreateFrameStorage(QSize size) {
	const auto width = size.width();
	const auto height = size.height();
	const auto widthAlign = kAlignImageBy / kPixelBytesSize;
	const auto neededWidth = width + ((width % widthAlign)
		? (widthAlign - (width % widthAlign))
		: 0);
	const auto perLine = neededWidth * kPixelBytesSize;
	const auto buffer = new uchar[perLine * height + kAlignImageBy];
	const auto cleanupData = static_cast<void *>(buffer);
	const auto address = reinterpret_cast<uintptr_t>(buffer);
	const auto alignedBuffer = buffer + ((address % kAlignImageBy)
		? (kAlignImageBy - (address % kAlignImageBy))
		: 0);
	return QImage(
		alignedBuffer,
		width,
		height,
		perLine,
		kImageFormat,
		AlignedImageBufferCleanupHandler,
		cleanupData);
}

void UnPremultiply(QImage &to, const QImage &from) {
	// This creates QImage::Format_ARGB32_Premultiplied, but we use it
	// as an image in QImage::Format_ARGB32 format.
	if (!GoodStorageForFrame(to, from.size())) {
		to = CreateFrameStorage(from.size());
	}
	const auto fromPerLine = from.bytesPerLine();
	const auto toPerLine = to.bytesPerLine();
	const auto width = from.width();
	const auto height = from.height();
	auto fromBytes = from.bits();
	auto toBytes = to.bits();
	if (fromPerLine != width * 4 || toPerLine != width * 4) {
		for (auto i = 0; i != height; ++i) {
			UnPremultiplyLine(toBytes, fromBytes, width);
			fromBytes += fromPerLine;
			toBytes += toPerLine;
		}
	} else {
		UnPremultiplyLine(toBytes, fromBytes, width * height);
	}
}

void PremultiplyInplace(QImage &image) {
	const auto perLine = image.bytesPerLine();
	const auto width = image.width();
	const auto height = image.height();
	auto bytes = image.bits();
	if (perLine != width * 4) {
		for (auto i = 0; i != height; ++i) {
			PremultiplyLine(bytes, bytes, width);
			bytes += perLine;
		}
	} else {
		PremultiplyLine(bytes, bytes, width * height);
	}
}

} // namespace FFmpeg
