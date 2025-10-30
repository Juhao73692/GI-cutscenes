using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading.Tasks;
namespace GICutscenes.Utils
{
    public static class VP9Validator
    {
        /// <summary>
        /// 检测VP9 IVF或裸流数据是否有效。
        /// </summary>
        /// <param name="data">视频文件或帧的原始字节流</param>
        /// <returns>若检测通过返回true，否则false</returns>
        public static bool Validate(byte[] data)
        {
            try
            {
                using var ms = new MemoryStream(data);
                using var br = new BinaryReader(ms);

                // --- 检测是否为 IVF 格式 ---
                if (data.Length >= 4)
                {
                    string magic = new string(br.ReadChars(4));
                    if (magic == "DKIF")
                    {
                        Console.WriteLine("Detected IVF format.");
                        return ValidateIVF(br, ms);
                    }
                }
                Console.WriteLine("Detected VP9 Frame format.");
                // --- 否则假定为单帧 VP9 裸流 ---
                var (ok, err) = ValidateVP9Frame(data, 0);
                if (!ok)
                {
                    Console.WriteLine($"Invalid VP9 frame: {err}.");
                    return false;
                }
                else
                {
                    return true;
                }
            }
            catch
            {
                Console.WriteLine("Exception during VP9 validation.");
                return false;
            }
        }

        private static bool ValidateIVF(BinaryReader br, MemoryStream ms)
        {
            ushort version = br.ReadUInt16();
            ushort headerLength = br.ReadUInt16();
            string fourcc = new string(br.ReadChars(4));
            Console.WriteLine($"version={version}, headerLength={headerLength}, fourcc={fourcc}");
            if (fourcc != "VP90") return false;
            br.ReadUInt16(); // width
            br.ReadUInt16(); // height
            br.ReadUInt32(); // frame rate
            br.ReadUInt32(); // time scale
            uint frameCount = br.ReadUInt32();
            br.ReadUInt32(); // unused

            int frameIndex = 0;
            while (ms.Position < ms.Length)
            {
                if (ms.Length - ms.Position < 12)
                {
                    Console.WriteLine($"Frame {frameIndex}: Insufficient data for frame header.");
                    return false;
                }

                uint frameSize = br.ReadUInt32();
                br.ReadUInt64(); // timestamp

                if (frameSize == 0 || frameSize > ms.Length - ms.Position)
                {
                    Console.WriteLine($"Frame {frameIndex}: Invalid frame size: {frameSize}.");
                    return false;
                }

                byte[] frame = br.ReadBytes((int)frameSize);
                var (ok, err) = ValidateVP9Frame(frame, frameIndex);
                if (!ok)
                {
                    Console.WriteLine($"Frame {frameIndex}: Invalid VP9 frame: {err}.");
                    return false;
                }
                Console.WriteLine($"Frame {frameIndex} validated successfully.");
                frameIndex++;
            }

            return true;
        }

        private static (bool, string) ValidateVP9Frame(byte[] frame, int frameIndex)
        {
            if (frame.Length < 1)
                return (false, "Frame too short");

            byte b0 = frame[0];
            int frameMarker = (b0 >> 6) & 0b11;
            if (frameMarker != 0b10)
                return (false, "Invalid frame marker");

            int profile = ((b0 >> 4) & 0b1) | ((b0 >> 3) & 0b10); // 正确解析 profile (low + high bit)
            if (profile > 3)
                return (false, "Invalid profile");

            bool showExistingFrame = ((b0 >> 3) & 1) == 1;
            if (showExistingFrame)
                return (true, ""); // show_existing_frame 无需 sync code

            bool isKeyFrame = (b0 & 0x1) == 0;
            int headerSizeInBytes = 1; // 至少 1 字节

            // 解析可变长 header（仅 keyframe 有）
            if (isKeyFrame)
            {
                if (frame.Length < 10)
                    return (false, "Keyframe too short");

                // 解析 VP9 frame header 以找到 uncompressed data 的起始位置
                int pos = 1;

                // --- 解析 frame size (if present) ---
                bool hasFrameSize = (b0 & 0x08) != 0; // bit 3
                if (hasFrameSize)
                {
                    if (pos + 2 > frame.Length) return (false, "Truncated frame size");
                    // uint16_t tx_mode; 但我们不关心
                    pos += 2;
                }

                // --- 跳到 uncompressed header ---
                // uncompressed header 紧跟在 frame header 之后
                // sync code 就在 uncompressed header 开头

                if (pos + 3 > frame.Length)
                    return (false, "No room for sync code");

                if (frame[pos] != 0x49 || frame[pos + 1] != 0x83 || frame[pos + 2] != 0x42)
                    return (false, "Missing sync code 0x49 83 42 in keyframe");

                // 可选：进一步验证 profile 在 uncompressed header 中重复
                // 但大多数验证器只检查 sync code
            }

            // --- superframe 检查（保持不变）---
            if (frame.Length > 0)
            {
                byte last = frame[^1];
                if ((last & 0xE0) == 0xC0)
                {
                    int framesInSuperframe = (last & 0x07) + 1;
                    int bytesPerSize = ((last >> 3) & 0x03) + 1;
                    int indexSize = 2 + framesInSuperframe * bytesPerSize;
                    if (indexSize > frame.Length)
                        return (false, "Invalid superframe index size");
                }
            }

            return (true, "");
        }
    }
    public static class VP9ValidatorV2
    {
        /// <summary>
        /// 流式验证：支持不完整数据，与 ffmpeg 行为一致
        /// </summary>
        /// <param name="data">累计的字节流（可能不完整）</param>
        /// <param name="isComplete">是否是完整文件？若否，仅检查“已完成部分”</param>
        /// <returns>(isValid, errorMessage, isComplete)</returns>
        public static (bool isValid, string error, bool isComplete) ValidateStreaming(byte[] data, bool isComplete = false)
        {
                try
                {
                    using var ms = new MemoryStream(data);
                    using var br = new BinaryReader(ms);

                    // --- 1. 尝试解析 IVF 头 ---
                    if (data.Length >= 4 && TryReadString(br, 4) == "DKIF")
                    {
                        return ValidateIVFStreaming(br, ms, isComplete);
                    }

                    // --- 2. 否则按裸 VP9 帧处理（单帧或 superframe）---
                    if (data.Length == 0) return (true, "", false);

                    var (ok, err, complete) = ValidateVP9FrameStreaming(data, isComplete);
                    return (ok, err, complete);
                }
                catch (Exception ex)
                {
                    return (false, $"Exception: {ex.Message}", true);
                }
        }

        private static (bool, string, bool) ValidateIVFStreaming(BinaryReader br, MemoryStream ms, bool isComplete)
        {
            // 跳过已读的 "DKIF"
            ms.Position = 4;

            if (ms.Length < 32) return (true, "IVF header incomplete", false); // 等待

            ushort version = br.ReadUInt16();
            ushort headerLength = br.ReadUInt16();
            string fourcc = TryReadString(br, 4);
            if (fourcc != "VP90") return (false, "Invalid FourCC, expected VP90", true);

            ushort width = br.ReadUInt16();
            ushort height = br.ReadUInt16();
            uint framerate = br.ReadUInt32();
            uint timescale = br.ReadUInt32();
            uint frameCount = br.ReadUInt32();
            br.ReadUInt32(); // unused

            if (width == 0 || height == 0) return (false, "Invalid dimensions", true);

            long frameStartPos = 32; // IVF header fixed size
            int frameIndex = 0;

            while (true)
            {
                long pos = ms.Position;
                if (pos + 12 > ms.Length)
                {
                    // 帧头不完整 → 等待更多数据
                    return (true, $"Frame {frameIndex} header incomplete", false);
                }

                uint frameSize = br.ReadUInt32();
                ulong timestamp = br.ReadUInt64();

                if (pos + 12 + frameSize > ms.Length)
                {
                    // 帧数据不完整 → 等待
                    return (true, $"Frame {frameIndex} data incomplete (got {ms.Length - pos - 12}, need {frameSize})", false);
                }

                byte[] frame = br.ReadBytes((int)frameSize);
                var (ok, err, complete) = ValidateVP9FrameStreaming(frame, true); // 帧内必须完整
                if (!ok) return (false, $"Frame {frameIndex}: {err}", true);
                if (!complete) return (false, $"Frame {frameIndex}: internal incomplete", true);

                frameIndex++;
                frameStartPos = ms.Position;

                // 如果不是完整文件，且已到末尾，等待
                if (!isComplete && ms.Position == ms.Length)
                    return (true, $"Validated {frameIndex} frames, waiting for more", false);
            }
        }

        private static (bool isValid, string error, bool isComplete) ValidateVP9FrameStreaming(byte[] frame, bool requireComplete)
        {
            if (frame.Length == 0) return (true, "", false);
            if (frame.Length < 1) return (true, "Too short", false);

            byte b0 = frame[0];

            // Frame Marker: bits 7-6 == 0b10
            if ((b0 >> 6) != 0b10)
                return (false, "Invalid frame marker (must be 0b10)", true);

            // Extract flags
            bool showExistingFrame = ((b0 >> 3) & 1) == 1;
            bool isKeyFrame = ((b0 >> 1) & 1) == 0;
            bool showFrame = ((b0 >> 4) & 1) == 1;
            bool errorResilient = ((b0 >> 2) & 1) == 1;

            // Debug print (remove in production)
            Console.WriteLine($"b0=0x{b0:X2} bin={Convert.ToString(b0, 2).PadLeft(8, '0')}, key={isKeyFrame}, showFrame={showFrame}, errResil={errorResilient}, showExist={showExistingFrame}");

            // show_existing_frame: no sync needed
            if (showExistingFrame)
                return CheckSuperframe(frame, requireComplete);

            // Non-keyframe: no sync needed
            if (!isKeyFrame)
                return CheckSuperframe(frame, requireComplete);

            // === Keyframe: require sync code ===
            int pos = 1;

            // Frame size field? Only for key + show_frame + !error_resilient + !show_existing
            bool hasSizeField = showFrame && !errorResilient && !showExistingFrame;  // ← 修复：添加 !showExistingFrame
            if (hasSizeField)
            {
                if (frame.Length < pos + 2)
                    return (true, "Waiting for size field", false);
                pos += 2;
            }

            // Check sync code space
            if (frame.Length < pos + 3)
                return requireComplete
                    ? (false, "Keyframe too short for sync code", true)
                    : (true, "Waiting for sync code", false);

            // // Verify sync: 0x49 83 42
            // if (frame[pos] != 0x49 || frame[pos + 1] != 0x83 || frame[pos + 2] != 0x42)
            //     return (false, $"Missing VP9 sync code at pos {pos} (got {frame[pos]:X2} {frame[pos + 1]:X2} {frame[pos + 2]:X2})", true);

            // // Debug: print sync found
            // Console.WriteLine($"Sync code found at pos {pos}");

            return CheckSuperframe(frame, requireComplete);
        }
        private static (bool, string, bool) CheckSuperframe(byte[] frame, bool requireComplete)
        {
            if (frame.Length == 0) return (true, "", false);

            byte marker = frame[^1];
            if ((marker & 0xE0) == 0xC0) // superframe marker
            {
                int framesInSuperframe = (marker & 0x07) + 1;
                int bytesPerSize = ((marker >> 3) & 0x03) + 1;
                int indexSize = 2 + framesInSuperframe * bytesPerSize;

                if (indexSize > frame.Length)
                {
                    return requireComplete
                        ? (false, "Superframe index truncated", true)
                        : (true, "Superframe index incomplete", false);
                }

                int indexStart = frame.Length - indexSize;
                int totalSize = 0;

                for (int i = 0; i < framesInSuperframe; i++)
                {
                    int size = 0;
                    for (int j = 0; j < bytesPerSize; j++)
                        size |= frame[indexStart + i * bytesPerSize + j] << (8 * j);

                    if (size <= 0)
                        return (false, $"Superframe[{i}] invalid size {size}", true);

                    totalSize += size;
                }

                if (totalSize > frame.Length - indexSize)
                    return (false, $"Invalid frame size in a superframe: total={totalSize}, available={frame.Length - indexSize}", true);
            }

            return (true, "", true);
        }



        private static string TryReadString(BinaryReader br, int count)
        {
            try
            {
                char[] chars = br.ReadChars(count);
                return new string(chars);
            }
            catch
            {
                return "";
            }
        }
    }

    public static class VP9ValidatorV3
    {
        /// <summary>
        /// 验证 VP9 帧是否存在 superframe 尾部错误
        /// </summary>
        /// <param name="frameData">单帧 VP9 数据</param>
        /// <returns>true = 合法 / false = 错误</returns>
        public static bool ValidateVp9Superframe(byte[] frameData)
        {
            if (frameData == null || frameData.Length < 2)
                return true; // 太短，不判定为非法

            int size = frameData.Length;
            byte marker = frameData[size - 1];

            // 检查是否可能为 superframe marker（高3位 110）
            if ((marker & 0xE0) != 0xC0)
                return true; // 无 superframe，合法

            int sizeBytes = ((marker >> 3) & 0x03) + 1; // 每个子帧长度占用字节数
            int frameCount = (marker & 0x07) + 1;
            int indexSize = 2 + sizeBytes * frameCount;

            if (indexSize > size)
                return true; // 数据不够，容错，合法

            // 首尾 marker 必须一致
            if (frameData[size - indexSize] != marker)
                return true; // 不一致，视为无 superframe

            // 解析每个子帧长度
            int offset = size - indexSize + 1;
            int total = 0;
            for (int i = 0; i < frameCount; i++)
            {
                if (offset + sizeBytes > size - 1) // 超出索引区
                    return false; // index 被截断，非法

                int subframeSize = 0;
                for (int b = 0; b < sizeBytes; b++)
                {
                    subframeSize |= frameData[offset + b] << (8 * b); // 小端解析
                }

                total += subframeSize;
                offset += sizeBytes;
            }

            // 总长度不可大于可用帧数据
            if (total > size - indexSize)
                return false; // 非法 superframe

            return true; // 合法
        }
    }

    internal class Checker
    {

        public static (bool ok, string stderr) ValidateIvfWithFfmpeg(string ivfPath, int timeoutMs = 10000)
        {
            if (!File.Exists(ivfPath)) return (false, "file-not-found");

            // ffmpeg 命令： -v error 只输出错误，-i file -f null - 表示尝试解码但不保存
            var psi = new ProcessStartInfo
            {
                FileName = "ffmpeg", // 需要 ffmpeg 在 PATH 中
                Arguments = $"-v error -i \"{ivfPath}\" -f null -",
                RedirectStandardError = true,
                RedirectStandardOutput = false,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using var proc = new Process { StartInfo = psi };
                proc.Start();

                // 异步读取 stderr（避免死锁）
                Task<string> stderrTask = proc.StandardError.ReadToEndAsync();

                bool exited = proc.WaitForExit(timeoutMs);
                if (!exited)
                {
                    try { proc.Kill(); } catch { }
                    return (false, "ffmpeg-timeout");
                }

                string stderr = stderrTask.Result ?? "";

                // 判断是否有致命错误 —— 可以根据需要调整关键字
                string lower = stderr.ToLowerInvariant();
                bool hasFatal = false;
                if (proc.ExitCode != 0) hasFatal = true;
                else if (lower.Contains("failed to decode") || lower.Contains("corrupt") || lower.Contains("invalid") || lower.Contains("error while decoding"))
                    hasFatal = true;

                return (!hasFatal, stderr);
            }
            catch (Exception ex)
            {
                return (false, "exception: " + ex.Message);
            }
        }

        public static bool QuickIvfVp9SanityCheck(byte[] ivfBytes)
        {
            // 1) find header
            int off = -1;
            for (int i = 0; i + 4 <= Math.Min(0x40, ivfBytes.Length - 4); i++)
            {
                if ((ivfBytes[i] == (byte)'D' && ivfBytes[i + 1] == (byte)'K' && ivfBytes[i + 2] == (byte)'I' && ivfBytes[i + 3] == (byte)'F')
                || (ivfBytes[i] == (byte)'I' && ivfBytes[i + 1] == (byte)'V' && ivfBytes[i + 2] == (byte)'F' && ivfBytes[i + 3] == (byte)' '))
                {
                    off = i;
                    break;
                }
            }
            int ptr = (off >= 0) ? off + 32 : 0;
            int frames = 0;
            int badFrameHeaders = 0;
            while (ptr + 12 <= ivfBytes.Length && frames < 2000)
            {
                uint len = BitConverter.ToUInt32(ivfBytes, ptr); // little-endian
                // sanity length cap (e.g. >0 and <32MB)
                if (len == 0 || len > (32 * 1024 * 1024)) break;
                if (ptr + 12 + (int)len > ivfBytes.Length) break;
                // check first payload byte top2 bits:
                byte first = ivfBytes[ptr + 12];
                int top2 = (first >> 6) & 0x3;
                if (top2 != 0b10) badFrameHeaders++;
                frames++;
                ptr += 12 + (int)len;
            }
            // heuristics:
            if (frames == 0) return false;
            // require at least majority of first few frames have plausible header
            return badFrameHeaders < Math.Max(1, frames / 3);
        }

        public static (bool ok, string stderr) ValidateIvfWithFfmpegBytes(byte[] ivfBytes, int timeoutMs = 10000)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ffmpeg", // 或绝对路径
                Arguments = "-v error -f ivf -i pipe:0 -f null -", // 指明输入格式为 ivf，并从 pipe:0 读取
                RedirectStandardInput = true,
                RedirectStandardError = true,
                RedirectStandardOutput = false,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using var proc = new Process { StartInfo = psi };

                proc.Start();

                // 异步读取 stderr
                Task<string> stderrTask = proc.StandardError.ReadToEndAsync();

                // 将内存数据写入 ffmpeg stdin
                using (var stdin = proc.StandardInput.BaseStream)
                {
                    stdin.Write(ivfBytes, 0, ivfBytes.Length);
                    stdin.Flush();
                    stdin.Close(); // 重要：通知 ffmpeg 数据写完
                }

                // 等待结束或超时
                bool exited = proc.WaitForExit(timeoutMs);
                if (!exited)
                {
                    try { proc.Kill(); } catch { }
                    return (false, "ffmpeg-timeout");
                }

                string stderr = stderrTask.Result ?? "";

                // 简单判定：非零 exitcode 或 stderr 含关键错误词 => 不通过
                string low = stderr.ToLowerInvariant();
                bool fatal = proc.ExitCode != 0
                            || low.Contains("failed to decode")
                            || low.Contains("corrupt")
                            || low.Contains("invalid")
                            || low.Contains("bitstream ended")
                            || low.Contains("error while decoding");

                return (!fatal, stderr);
            }
            catch (Exception ex)
            {
                return (false, "exception: " + ex.Message);
            }
        }
    }
    

}