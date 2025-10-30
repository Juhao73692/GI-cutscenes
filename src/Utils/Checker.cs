using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
namespace GICutscenes.Utils
{
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