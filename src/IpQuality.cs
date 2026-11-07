// IP 质量测试：绿色单文件小工具。用 ICMP 或 TCP 连接测延迟、丢包、抖动；
// 指定实体网卡后，测试包从这张网卡直接发出，不经过 v2rayN 的 TUN。
// 不写注册表、不写配置文件、不常驻；关窗即退出进程。只支持 IPv4。
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Shapes;
using Microsoft.Win32;

namespace IpQuality
{
    static class Program
    {
        [STAThread]
        static void Main()
        {
            var app = new Application();
            app.ShutdownMode = ShutdownMode.OnMainWindowClose;
            app.Run(new MainWindow());
        }
    }

    // ---------- 配色（取自 dataviz 参考色板：系列蓝、状态色、墨色层级、发丝线） ----------
    class Theme
    {
        public bool Dark;
        public Color Page, Surface, Border, Ink, Ink2, Muted, Grid, Baseline, Field, FieldBorder, Accent, Wash, Critical, Good, Warning, Scroll;

        public static Theme Detect()
        {
            bool dark = false;
            try
            {
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    object v = k == null ? null : k.GetValue("AppsUseLightTheme");
                    dark = v is int && (int)v == 0;
                }
            }
            catch { }
            var t = new Theme();
            t.Dark = dark;
            t.Critical = C("#d03b3b"); t.Good = C("#0ca30c"); t.Warning = C("#fab219");
            if (dark)
            {
                t.Page = C("#0d0d0d"); t.Surface = C("#1a1a19"); t.Border = C("#1AFFFFFF");
                t.Ink = C("#f0efec"); t.Ink2 = C("#c3c2b7"); t.Muted = C("#898781");
                t.Grid = C("#2c2c2a"); t.Baseline = C("#383835");
                t.Field = C("#222220"); t.FieldBorder = C("#3d3d3a");
                t.Accent = C("#3987e5"); t.Wash = C("#1d2d42"); t.Scroll = C("#4a4a46");
            }
            else
            {
                t.Page = C("#f3f2ee"); t.Surface = C("#ffffff"); t.Border = C("#1A0B0B0B");
                t.Ink = C("#0b0b0b"); t.Ink2 = C("#52514e"); t.Muted = C("#898781");
                t.Grid = C("#e1e0d9"); t.Baseline = C("#c3c2b7");
                t.Field = C("#ffffff"); t.FieldBorder = C("#d3d2cb");
                t.Accent = C("#2a78d6"); t.Wash = C("#e8f1fc"); t.Scroll = C("#c9c8c1");
            }
            return t;
        }

        public static Color C(string hex) { return (Color)ColorConverter.ConvertFromString(hex); }
        public static string Hex(Color c) { return string.Format("#{0:X2}{1:X2}{2:X2}{3:X2}", c.A, c.R, c.G, c.B); }
        public static SolidColorBrush B(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
        public static SolidColorBrush B(Color c, double alpha)
        {
            var b = new SolidColorBrush(Color.FromArgb((byte)(alpha * 255), c.R, c.G, c.B)); b.Freeze(); return b;
        }
    }

    // ---------- 数据 ----------
    class Probe
    {
        public int Seq;
        public bool Ok;
        public double Ms;
        public string Note;
    }

    class Nic
    {
        public string Name, Desc;
        public IPAddress Ip;
        public int Index;
        public bool Virtual, Gateway;
    }

    class Settings
    {
        public string TargetText;
        public IPAddress Target;
        public Nic Source;          // null = 按系统路由
        public bool Tcp, Trace;
        public int Port, Count, Interval, Timeout, Size;
    }

    // ---------- 网络 ----------
    static class Net
    {
        const int IP_UNICAST_IF = 31;

        public static List<Nic> LoadNics()
        {
            var list = new List<Nic>();
            string[] virtualWords = { "tun", "tap", "wintun", "wireguard", "sing", "clash", "mihomo", "meta", "v2ray", "xray",
                                      "vpn", "virtual", "vmware", "virtualbox", "hyper-v", "vethernet", "zerotier", "tailscale",
                                      "npcap", "pseudo", "loopback" };
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                IPInterfaceProperties p;
                IPv4InterfaceProperties v4;
                try { p = ni.GetIPProperties(); v4 = p.GetIPv4Properties(); }
                catch { continue; }
                if (v4 == null) continue;
                IPAddress ip = null;
                foreach (var ua in p.UnicastAddresses)
                {
                    var b = ua.Address.GetAddressBytes();
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork && !(b[0] == 169 && b[1] == 254)) { ip = ua.Address; break; }
                }
                if (ip == null) continue;
                string s = (ni.Name + " " + ni.Description).ToLowerInvariant();
                var n = new Nic();
                n.Name = ni.Name; n.Desc = ni.Description; n.Ip = ip; n.Index = v4.Index;
                n.Gateway = p.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
                n.Virtual = ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel || ni.NetworkInterfaceType == NetworkInterfaceType.Ppp
                            || virtualWords.Any(w => s.Contains(w));
                list.Add(n);
            }
            return list.OrderBy(n => n.Virtual ? 2 : (n.Gateway ? 0 : 1)).ToList();
        }

        // 绑定源地址 + IP_UNICAST_IF：两道保险，让包只从这张网卡出去
        public static void BindTo(Socket s, Nic nic)
        {
            if (nic == null) return;
            try { s.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)IP_UNICAST_IF, IPAddress.HostToNetworkOrder(nic.Index)); }
            catch { }
            s.Bind(new IPEndPoint(nic.Ip, 0));
        }

        // 域名解析：指定网卡时自己查（避开 v2rayN 的 fake-ip），否则用系统 DNS。
        // v2rayN 的 strict_route 会拦截 TUN 以外的 53 端口，所以先走阿里 DoH（HTTPS 443），再试普通 UDP 53。
        public static IPAddress Resolve(string host, Nic nic, out string via)
        {
            if (nic == null)
            {
                foreach (var a in Dns.GetHostAddresses(host))
                    if (a.AddressFamily == AddressFamily.InterNetwork) { via = "系统 DNS"; return a; }
                throw new Exception("这个域名没有 IPv4 地址");
            }
            string err = "域名解析失败";
            foreach (var server in new[] { "223.5.5.5", "223.6.6.6" })
            {
                try
                {
                    var a = QueryDoh(host, server, nic);
                    if (a != null) { via = "阿里 DNS " + server + "（HTTPS）"; return a; }
                    err = "这个域名没有 IPv4 地址";
                }
                catch (Exception e)
                {
                    if (e.Message == "域名不存在") throw;
                    err = "域名解析失败：" + e.Message;
                }
            }
            foreach (var server in new[] { "223.5.5.5", "119.29.29.29" })
            {
                try
                {
                    var a = QueryA(host, IPAddress.Parse(server), nic);
                    if (a != null) { via = server; return a; }
                    err = "这个域名没有 IPv4 地址";
                }
                catch (Exception e) { if (!err.StartsWith("域名")) err = e.Message; }
            }
            throw new Exception(err);
        }

        static IPAddress QueryDoh(string host, string server, Nic nic)
        {
            if (!Regex.IsMatch(host, @"^[A-Za-z0-9.-]+$")) throw new Exception("域名格式不对");
            var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                BindTo(s, nic);
                s.SendTimeout = s.ReceiveTimeout = 3000;
                var ar = s.BeginConnect(new IPEndPoint(IPAddress.Parse(server), 443), null, null);
                if (!ar.AsyncWaitHandle.WaitOne(3000)) throw new Exception("连不上 " + server);
                s.EndConnect(ar);
                using (var ssl = new System.Net.Security.SslStream(new NetworkStream(s, true), false))
                {
                    ssl.AuthenticateAsClient(server, null, System.Security.Authentication.SslProtocols.Tls12, true);
                    var req = Encoding.ASCII.GetBytes("GET /resolve?name=" + host + "&type=1 HTTP/1.1\r\nHost: " + server + "\r\nConnection: close\r\n\r\n");
                    ssl.Write(req);
                    string body = new System.IO.StreamReader(ssl, Encoding.UTF8).ReadToEnd();
                    if (Regex.IsMatch(body, "\"Status\"\\s*:\\s*3")) throw new Exception("域名不存在");
                    var m = Regex.Match(body, "\"type\"\\s*:\\s*1\\s*,\\s*\"data\"\\s*:\\s*\"(\\d{1,3}(?:\\.\\d{1,3}){3})\"");
                    return m.Success ? IPAddress.Parse(m.Groups[1].Value) : null;
                }
            }
            finally { s.Close(); }
        }

        static IPAddress QueryA(string host, IPAddress server, Nic nic)
        {
            ushort id = (ushort)new Random().Next(1, 65535);
            var q = new List<byte> { (byte)(id >> 8), (byte)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
            foreach (var label in host.TrimEnd('.').Split('.'))
            {
                var b = Encoding.ASCII.GetBytes(label);
                if (b.Length == 0 || b.Length > 63) throw new Exception("域名格式不对");
                q.Add((byte)b.Length); q.AddRange(b);
            }
            q.AddRange(new byte[] { 0, 0, 1, 0, 1 });
            using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
            {
                BindTo(s, nic);
                s.ReceiveTimeout = 2000;
                s.SendTo(q.ToArray(), new IPEndPoint(server, 53));
                var buf = new byte[1500];
                EndPoint from = new IPEndPoint(IPAddress.Any, 0);
                int n = s.ReceiveFrom(buf, ref from);
                if (n < 12 || buf[0] != (byte)(id >> 8) || buf[1] != (byte)id) throw new Exception("DNS 回复不对");
                if ((buf[3] & 0xF) == 3) throw new Exception("域名不存在");
                int qd = (buf[4] << 8) | buf[5], an = (buf[6] << 8) | buf[7], p = 12;
                for (int i = 0; i < qd; i++) p = SkipName(buf, p) + 4;
                for (int i = 0; i < an && p + 10 <= n; i++)
                {
                    p = SkipName(buf, p);
                    int type = (buf[p] << 8) | buf[p + 1], len = (buf[p + 8] << 8) | buf[p + 9];
                    p += 10;
                    if (type == 1 && len == 4) return new IPAddress(new[] { buf[p], buf[p + 1], buf[p + 2], buf[p + 3] });
                    p += len;
                }
                return null;
            }
        }

        static int SkipName(byte[] b, int p)
        {
            while (true)
            {
                int len = b[p];
                if (len == 0) return p + 1;
                if ((len & 0xC0) == 0xC0) return p + 2;
                p += len + 1;
            }
        }

        public static Probe Tcp(IPAddress dst, int port, Nic nic, int timeout)
        {
            var r = new Probe();
            using (var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    s.NoDelay = true;
                    BindTo(s, nic);
                    var sw = Stopwatch.StartNew();
                    var ar = s.BeginConnect(new IPEndPoint(dst, port), null, null);
                    bool done = ar.AsyncWaitHandle.WaitOne(timeout);
                    double ms = sw.Elapsed.TotalMilliseconds;
                    if (!done) { r.Note = "超时"; return r; }
                    s.EndConnect(ar);
                    r.Ok = true; r.Ms = ms; r.Note = "连接成功";
                }
                catch (SocketException e)
                {
                    r.Note = e.SocketErrorCode == SocketError.ConnectionRefused ? "端口拒绝连接"
                           : e.SocketErrorCode == SocketError.NetworkUnreachable ? "网络不可达"
                           : e.SocketErrorCode == SocketError.HostUnreachable ? "主机不可达"
                           : "失败（" + e.SocketErrorCode + "）";
                }
            }
            return r;
        }
    }

    sealed class Icmp : IDisposable
    {
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern IntPtr IcmpCreateFile();
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern bool IcmpCloseHandle(IntPtr h);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint IcmpSendEcho2Ex(IntPtr h, IntPtr evt, IntPtr apc, IntPtr apcCtx, uint src, uint dst,
                                           IntPtr data, ushort size, IntPtr opts, IntPtr reply, uint replySize, uint timeout);

        IntPtr handle, req, reply;
        int size, replySize;

        public Icmp(int size)
        {
            this.size = size;
            handle = IcmpCreateFile();
            if (handle == new IntPtr(-1)) throw new Exception("无法创建 ICMP 句柄");
            var data = new byte[Math.Max(size, 1)];
            for (int i = 0; i < data.Length; i++) data[i] = (byte)('a' + i % 23);
            req = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, req, data.Length);
            replySize = size + 512;
            reply = Marshal.AllocHGlobal(replySize);
        }

        static uint Addr(IPAddress ip) { return ip == null ? 0u : BitConverter.ToUInt32(ip.GetAddressBytes(), 0); }

        public Probe Send(IPAddress dst, Nic nic, int timeout)
        {
            var r = new Probe();
            var sw = Stopwatch.StartNew();
            uint n = IcmpSendEcho2Ex(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, Addr(nic == null ? null : nic.Ip), Addr(dst),
                                     req, (ushort)size, IntPtr.Zero, reply, (uint)replySize, (uint)timeout);
            double ms = sw.Elapsed.TotalMilliseconds;
            if (n == 0)
            {
                int err = Marshal.GetLastWin32Error();
                r.Note = err == 11010 ? "超时" : StatusText((uint)err);
                return r;
            }
            uint status = (uint)Marshal.ReadInt32(reply, 4);
            if (status != 0)
            {
                var from = new IPAddress((long)(uint)Marshal.ReadInt32(reply, 0));
                r.Note = StatusText(status) + "（来自 " + from + "）";
                return r;
            }
            byte ttl = Marshal.ReadByte(reply, IntPtr.Size == 8 ? 24 : 20);
            r.Ok = true; r.Ms = ms; r.Note = "TTL=" + ttl;
            return r;
        }

        static string StatusText(uint s)
        {
            switch (s)
            {
                case 11002: return "目标网络不可达";
                case 11003: return "目标主机不可达";
                case 11004: return "协议不可达";
                case 11005: return "端口不可达";
                case 11010: return "超时";
                case 11013: return "传输中 TTL 过期";
                case 11018: return "目标地址无效";
                case 1231: return "网络不可达";
                case 1232: return "主机不可达";
                default: return "失败（代码 " + s + "）";
            }
        }

        public void Dispose()
        {
            if (handle != IntPtr.Zero) { IcmpCloseHandle(handle); handle = IntPtr.Zero; }
            if (req != IntPtr.Zero) { Marshal.FreeHGlobal(req); req = IntPtr.Zero; }
            if (reply != IntPtr.Zero) { Marshal.FreeHGlobal(reply); reply = IntPtr.Zero; }
        }
    }

    // ---------- 路由追踪：每轮对 TTL 1..N 同时发 ICMP（异步），像 mtr / itdog 一样逐跳统计 ----------
    class Hop
    {
        public int Ttl, Sent, Recv, LocTries;
        public IPAddress Ip;
        public string Loc;
        public double Last = -1, Min = double.MaxValue, Max, Sum;
        public List<bool> Hist = new List<bool>();
        public double Loss { get { return Sent == 0 ? 0 : (Sent - Recv) * 100.0 / Sent; } }
    }

    class TraceState
    {
        public List<Hop> Hops = new List<Hop>();   // 下标 = TTL - 1
        public int Dest, MaxSeen;                   // Dest = 终点在第几跳（0 = 还没到达）
        public bool GeoBusy;

        public Hop Get(int ttl)
        {
            while (Hops.Count < ttl) Hops.Add(new Hop { Ttl = Hops.Count + 1 });
            return Hops[ttl - 1];
        }

        public int Visible { get { return Dest > 0 ? Dest : Math.Min(Hops.Count, Math.Max(MaxSeen + 1, 1)); } }
    }

    sealed class TraceIcmp : IDisposable
    {
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern IntPtr IcmpCreateFile();
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern bool IcmpCloseHandle(IntPtr h);
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern uint IcmpParseReplies(IntPtr reply, uint size);
        [DllImport("iphlpapi.dll", SetLastError = true)]
        static extern uint IcmpSendEcho2Ex(IntPtr h, IntPtr evt, IntPtr apc, IntPtr apcCtx, uint src, uint dst,
                                           IntPtr data, ushort size, IntPtr opts, IntPtr reply, uint replySize, uint timeout);

        public const int MaxHops = 30;
        public struct R { public bool Got; public IPAddress From; public uint Status; public double Ms; }

        readonly IntPtr[] h = new IntPtr[MaxHops + 1], rep = new IntPtr[MaxHops + 1], opt = new IntPtr[MaxHops + 1];
        readonly ManualResetEvent[] ev = new ManualResetEvent[MaxHops + 1];
        readonly bool[] busy = new bool[MaxHops + 1];
        readonly IntPtr req;
        readonly int size, repSize;

        public TraceIcmp(int size)
        {
            this.size = size;
            var data = new byte[Math.Max(size, 1)];
            for (int i = 0; i < data.Length; i++) data[i] = (byte)('a' + i % 23);
            req = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, req, data.Length);
            repSize = size + 512;
            for (int t = 1; t <= MaxHops; t++)
            {
                h[t] = IcmpCreateFile();
                if (h[t] == new IntPtr(-1)) throw new Exception("无法创建 ICMP 句柄");
                rep[t] = Marshal.AllocHGlobal(repSize);
                opt[t] = Marshal.AllocHGlobal(16);          // IP_OPTION_INFORMATION：Ttl 在第 0 字节
                for (int k = 0; k < 16; k++) Marshal.WriteByte(opt[t], k, 0);
                Marshal.WriteByte(opt[t], 0, (byte)t);
                ev[t] = new ManualResetEvent(false);
            }
        }

        static uint Addr(IPAddress ip) { return ip == null ? 0u : BitConverter.ToUInt32(ip.GetAddressBytes(), 0); }

        public R[] Round(IPAddress dst, Nic nic, int upto, int timeout)
        {
            var res = new R[upto + 1];
            uint src = Addr(nic == null ? null : nic.Ip), d = Addr(dst);
            for (int t = 1; t <= upto; t++)
            {
                for (int k = 0; k < 16; k += 4) Marshal.WriteInt32(rep[t], k, 0);
                ev[t].Reset();
                uint n = IcmpSendEcho2Ex(h[t], ev[t].SafeWaitHandle.DangerousGetHandle(), IntPtr.Zero, IntPtr.Zero, src, d,
                                         req, (ushort)size, opt[t], rep[t], (uint)repSize, (uint)timeout);
                int err = Marshal.GetLastWin32Error();
                if (n == 0 && err == 997) busy[t] = true;        // ERROR_IO_PENDING：已异步发出
                else if (n != 0) Parse(t, ref res[t]);
                else res[t].Status = (uint)err;
            }
            var sw = Stopwatch.StartNew();
            for (int t = 1; t <= upto; t++)
            {
                if (!busy[t]) continue;
                int left = timeout + 500 - (int)sw.ElapsedMilliseconds;
                if (ev[t].WaitOne(Math.Max(0, left))) { busy[t] = false; Parse(t, ref res[t]); }
                else res[t].Status = 11010;
            }
            return res;
        }

        void Parse(int t, ref R r)
        {
            uint n = IcmpParseReplies(rep[t], (uint)repSize);
            uint st = n > 0 ? (uint)Marshal.ReadInt32(rep[t], 4) : (uint)Marshal.GetLastWin32Error();
            uint a = (uint)Marshal.ReadInt32(rep[t], 0);
            r.Status = st;
            if (a != 0 && st != 11010)
            {
                r.Got = true; r.From = new IPAddress((long)a); r.Ms = (uint)Marshal.ReadInt32(rep[t], 8);
            }
        }

        public void Dispose()
        {
            for (int t = 1; t <= MaxHops; t++)
            {
                if (ev[t] == null) continue;
                if (busy[t]) ev[t].WaitOne(3000);
                if (h[t] != IntPtr.Zero) IcmpCloseHandle(h[t]);
                Marshal.FreeHGlobal(rep[t]); Marshal.FreeHGlobal(opt[t]); ev[t].Close();
            }
            Marshal.FreeHGlobal(req);
        }
    }

    // 归属地：内网段本地判断；公网 IP 批量查 ip-api.com（中文），只发 IP 本身
    static class Geo
    {
        public static string Local(IPAddress ip)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] < 32) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254)) return "局域网";
            if (b[0] == 100 && b[1] >= 64 && b[1] < 128) return "运营商内网";
            return null;
        }

        public static Dictionary<string, string> Lookup(List<string> ips)
        {
            var res = new Dictionary<string, string>();
            string body = "[" + string.Join(",", ips.Select(i => "\"" + i + "\"")) + "]";
            using (var wc = new WebClient())
            {
                wc.Encoding = Encoding.UTF8;
                wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                string json = wc.UploadString("http://ip-api.com/batch?lang=zh-CN&fields=status,country,regionName,city,isp,as,query", body);
                foreach (Match m in Regex.Matches(json, @"\{[^{}]*\}"))
                {
                    string o = m.Value, q = F(o, "query");
                    if (q.Length == 0) continue;
                    if (F(o, "status") != "success") { res[q] = ""; continue; }
                    string country = F(o, "country");
                    var parts = new[] { country == "中国" ? "" : country, F(o, "regionName"), F(o, "city") }.Where(x => x.Length > 0).Distinct();
                    string asn = F(o, "as").Split(' ')[0], isp = Carrier(asn, F(o, "isp"));
                    res[q] = string.Join("/", parts) + (asn.Length > 0 ? " · " + asn : "") + (isp.Length > 0 ? " " + isp : "");
                }
            }
            return res;
        }

        // 常见运营商用中文简称，其余保留原名
        static readonly Dictionary<string, string> Short = new Dictionary<string, string> {
            { "AS9808", "移动" }, { "AS56040", "移动" }, { "AS56041", "移动" }, { "AS56042", "移动" }, { "AS56046", "移动" }, { "AS56047", "移动" },
            { "AS24400", "移动" }, { "AS24444", "移动" }, { "AS58453", "移动国际 CMI" }, { "AS58807", "移动国际 CMIN2" },
            { "AS4837", "联通" }, { "AS4808", "联通" }, { "AS17621", "联通" }, { "AS17622", "联通" }, { "AS9929", "联通 A 网" }, { "AS10099", "联通国际" },
            { "AS4134", "电信" }, { "AS4812", "电信" }, { "AS4809", "电信 CN2" }, { "AS23764", "电信国际 CTG" },
            { "AS2914", "NTT" }, { "AS4637", "Telstra" }, { "AS3491", "PCCW" }, { "AS6453", "TATA" }, { "AS1299", "Arelion" },
            { "AS174", "Cogent" }, { "AS3356", "Lumen" }, { "AS6939", "HE" }, { "AS13335", "Cloudflare" }, { "AS9269", "香港宽频 HKBN" },
            { "AS4760", "HKT" }, { "AS9304", "HGC" } };

        static string Carrier(string asn, string isp)
        {
            string s;
            if (Short.TryGetValue(asn, out s)) return s;
            isp = Regex.Replace(isp, @"[,.]?\s+(Co\.?,?\s*Ltd\.?|Limited|Inc\.?|LLC|Corporation|Corp\.?|Pte\.? Ltd\.?|Communications?|Technology|Network)\b.*$", "", RegexOptions.IgnoreCase);
            return isp.Length > 28 ? isp.Substring(0, 28) + "…" : isp;
        }

        static string F(string obj, string key)
        {
            var m = Regex.Match(obj, "\"" + key + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
            return m.Success ? Regex.Unescape(m.Groups[1].Value) : "";
        }
    }

    // 截图脱敏用（只有自测版会打开）：除终点外的 IP 只保留前两段
    static class IpMask
    {
        public static bool Mask;
        public static string Ip(IPAddress ip)
        {
            if (!Mask) return ip.ToString();
            var b = ip.GetAddressBytes();
            return b[0] + "." + b[1] + ".x.x";
        }
    }

    // 逐跳表：每跳的 IP、归属、丢包、延迟，以及最近 60 轮的回应条（红 = 这一轮没回应）
    class HopTable : FrameworkElement
    {
        const double HeadH = 30, RowH = 28, FootH = 44;
        public TraceState State;
        public ScrollViewer Host;          // 表头固定在可视区顶部，需要知道滚动位置
        readonly Brush ink, ink2, muted, wash, good, warn, crit, surface;
        readonly Pen grid, baseline, okLine;
        public const int HistMax = 300;
        static readonly string[] Heads = { "跳", "IP", "归属（仅供参考）", "丢包", "已发", "最新 (ms)", "最快 (ms)", "最慢 (ms)", "平均 (ms)", "" };
        // 归属（第 2 列）按内容定宽，回应条（最后一列）拿走剩下的全部宽度
        static readonly double[] Widths = { 34, 124, 0, 66, 46, 64, 64, 64, 64, 0 };

        public HopTable(Theme t)
        {
            ink = Theme.B(t.Ink); ink2 = Theme.B(t.Ink2); muted = Theme.B(t.Muted); wash = Theme.B(t.Wash);
            good = Theme.B(t.Good); warn = Theme.B(t.Warning); crit = Theme.B(t.Critical); surface = Theme.B(t.Surface);
            grid = new Pen(Theme.B(t.Grid), 1); grid.Freeze();
            baseline = new Pen(Theme.B(t.Baseline), 1); baseline.Freeze();
            okLine = new Pen(Theme.B(t.Good), 2); okLine.Freeze();
        }

        int Rows()
        {
            if (State == null) return 0;
            lock (State) return State.Visible;
        }

        const double MinBar = 150;   // 回应条至少这么宽

        double LocNeed()
        {
            double need = 160;
            if (State != null)
                lock (State)
                    for (int r = 0; r < State.Visible; r++)
                    {
                        var hp = State.Hops[r];
                        string s = hp.Ip == null ? "不回应 ping（常见，不影响使用）" : (hp.Loc ?? "查询中…");
                        need = Math.Max(need, Txt(s, 12.5, ink2, false, 0).Width + 24);
                    }
            return Math.Min(need, 640);
        }

        // 宽度 = 表格完整显示所需的最小宽度；ScrollViewer 视口更宽时会把表格拉伸到视口宽
        protected override Size MeasureOverride(Size a)
        {
            return new Size(Widths.Sum() + 4 + LocNeed() + MinBar, HeadH + Math.Max(Rows(), 1) * RowH + FootH);
        }

        FormattedText Txt(string s, double size, Brush b, bool bold, double maxW)
        {
            var tf = new Typeface(new FontFamily("Segoe UI, Microsoft YaHei UI"), FontStyles.Normal, bold ? FontWeights.SemiBold : FontWeights.Normal, FontStretches.Normal);
            var ft = new FormattedText(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, tf, size, b, VisualTreeHelper.GetDpi(this).PixelsPerDip);
            if (maxW > 4) { ft.MaxTextWidth = maxW; ft.MaxLineCount = 1; ft.Trimming = TextTrimming.CharacterEllipsis; }
            return ft;
        }

        static string Ms(double v) { return v < 0 ? "—" : LatencyChart.Ms(v); }

        protected override void OnRender(DrawingContext dc)
        {
            double W = ActualWidth;
            dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, W, ActualHeight));
            var w = (double[])Widths.Clone();
            // 归属列总是按内容给足；窗口不够宽时表格比窗口宽，底下出现横向滚动条
            w[2] = LocNeed();
            w[9] = Math.Max(MinBar, W - Widths.Sum() - 4 - w[2]);
            // 回应条每轮约 3 像素：窗口越宽，能看到的轮数越多（最多 300 轮）
            int slots = (int)Math.Max(30, Math.Min(HistMax, Math.Floor((w[9] - 14) / 3)));
            var x = new double[w.Length + 1];
            for (int i = 0; i < w.Length; i++) x[i + 1] = x[i] + w[i];
            bool[] right = { false, false, false, true, true, true, true, true, true, false };

            if (State == null)
            {
                var e = Txt("选「路由追踪」，填 IP 后开始；每一轮同时探测每一跳", 13, muted, false, 0);
                dc.DrawText(e, new Point((W - e.Width) / 2, HeadH + 16));
            }
            else lock (State)
            {
                int n = State.Visible;
                for (int r = 0; r < n; r++)
                {
                    var hp = State.Hops[r];
                    double y = HeadH + r * RowH;
                    bool dest = State.Dest == hp.Ttl;
                    if (dest) dc.DrawRectangle(wash, null, new Rect(0, y, W, RowH));
                    else dc.DrawLine(grid, new Point(0, y + RowH - 0.5), new Point(W, y + RowH - 0.5));
                    bool any = hp.Recv > 0;
                    double loss = hp.Loss;
                    // 一次都没回应的跳是路由器不回 ping，不算丢包，灰色显示
                    Brush lb = !any ? muted : loss == 0 ? ink2 : loss < 5 ? warn : crit;
                    string[] cells = {
                        hp.Ttl.ToString(), hp.Ip == null ? "*" : dest ? hp.Ip.ToString() : IpMask.Ip(hp.Ip),
                        hp.Ip == null ? "不回应 ping（常见，不影响使用）" : (hp.Loc ?? "查询中…"),
                        !any ? "—" : loss.ToString(loss == 0 || loss == 100 ? "0" : "0.0") + "%", hp.Sent.ToString(),
                        any ? Ms(hp.Last) : "—", any ? Ms(hp.Min) : "—", any ? Ms(hp.Max) : "—", any ? Ms(hp.Sum / hp.Recv) : "—" };
                    for (int i = 0; i < cells.Length; i++)
                    {
                        var b = i == 3 ? lb : i == 2 ? ink2 : (i == 1 && hp.Ip == null) ? muted : ink;
                        var t = Txt(cells[i], 12.5, b, i == 3 || (dest && i == 1), w[i] - 10);
                        double tx = right[i] ? x[i + 1] - 8 - t.Width : x[i];
                        dc.DrawText(t, new Point(tx, y + (RowH - t.Height) / 2));
                    }
                    // 回应条：从左往右按时间排，最新的在最右端；绿色底线 = 有回应，红色竖条 = 那一轮没回应
                    double bx0 = x[9] + 14, bw = w[9] - 14, slot = bw / slots, top = y + 6, bot = y + RowH - 7;
                    int cnt = Math.Min(hp.Hist.Count, slots), off = hp.Hist.Count - cnt;
                    if (cnt > 0) dc.DrawLine(any ? okLine : grid, new Point(bx0, bot), new Point(bx0 + cnt * slot, bot));
                    for (int k = 0; k < cnt && any; k++)
                        if (!hp.Hist[off + k]) dc.DrawRectangle(crit, null, new Rect(bx0 + k * slot, top, Math.Max(1.5, slot * 0.7), bot - top + 1));
                }
                double fy = HeadH + Math.Max(n, 1) * RowH + 8;
                string note = State.Dest > 0 ? "底色那一行是终点（第 " + State.Dest + " 跳）。" : "还没到达终点；终点若禁 ping，会一直显示到最后有回应的那一跳。";
                dc.DrawText(Txt(note + "中间某跳丢包、但后面各跳和终点不丢 = 那台路由器限速回复，不是真丢包，以终点一行为准。", 12, muted, false, W - 4), new Point(0, fy));
                dc.DrawText(Txt("归属地由 ip-api.com 查询（只发送各跳 IP），仅供参考。", 12, muted, false, W - 4), new Point(0, fy + 18));
            }

            // 表头最后画，固定在可视区顶部，滚动时不跟着走
            double hy = Host == null ? 0 : Host.VerticalOffset;
            dc.DrawRectangle(surface, null, new Rect(0, hy, W, HeadH));
            for (int i = 0; i < Heads.Length; i++)
            {
                var t = Txt(i == 9 ? "最近 " + slots + " 轮" + (w[9] > 260 ? "（红 = 没回应）" : "") : Heads[i], 12, muted, false, w[i] - 8);
                double tx = right[i] ? x[i + 1] - 8 - t.Width : x[i] + (i == 9 ? 14 : 0);
                dc.DrawText(t, new Point(tx, hy + (HeadH - t.Height) / 2));
            }
            dc.DrawLine(baseline, new Point(0, hy + HeadH - 0.5), new Point(W, hy + HeadH - 0.5));
        }

        public string Text()
        {
            if (State == null) return "";
            var sb = new StringBuilder("跳  IP               丢包     已发   最新    最快    最慢    平均   归属");
            lock (State)
                for (int r = 0; r < State.Visible; r++)
                {
                    var hp = State.Hops[r];
                    bool any = hp.Recv > 0;
                    sb.Append("\r\n").Append(hp.Ttl.ToString().PadRight(4)).Append((hp.Ip == null ? "*" : State.Dest == hp.Ttl ? hp.Ip.ToString() : IpMask.Ip(hp.Ip)).PadRight(17))
                      .Append((any ? hp.Loss.ToString("0.#") + "%" : "—").PadLeft(6)).Append(hp.Sent.ToString().PadLeft(7))
                      .Append((any ? Ms(hp.Last) : "—").PadLeft(8)).Append((any ? Ms(hp.Min) : "—").PadLeft(8))
                      .Append((any ? Ms(hp.Max) : "—").PadLeft(8)).Append((any ? Ms(hp.Sum / hp.Recv) : "—").PadLeft(8))
                      .Append("   ").Append(hp.Loc ?? "").Append(State.Dest == hp.Ttl ? "  ← 终点" : "");
                }
            return sb.ToString();
        }
    }

    // ---------- 延迟走势图：单系列折线 + 丢包竖条 + 悬停十字线与提示 ----------
    class LatencyChart : FrameworkElement
    {
        const int Window = 600;
        readonly Theme th;
        readonly Brush ink, ink2, muted, surface, field, series, area, lossBand, critical;
        readonly Pen grid, baseline, line, ring, cross, tipBorder;
        public List<Probe> Data = new List<Probe>();
        public int Planned;
        int hover = -1;

        public LatencyChart(Theme t)
        {
            th = t;
            ink = Theme.B(t.Ink); ink2 = Theme.B(t.Ink2); muted = Theme.B(t.Muted); surface = Theme.B(t.Surface); field = Theme.B(t.Field);
            series = Theme.B(t.Accent); area = Theme.B(t.Accent, 0.10); lossBand = Theme.B(t.Critical, 0.22); critical = Theme.B(t.Critical);
            grid = P(t.Grid, 1); baseline = P(t.Baseline, 1); ring = P(t.Surface, 2); cross = P(t.Muted, 1); tipBorder = P(t.FieldBorder, 1);
            line = new Pen(series, 2) { LineJoin = PenLineJoin.Round, StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };
            line.Freeze();
            ClipToBounds = true;
        }

        static Pen P(Color c, double w) { var p = new Pen(Theme.B(c), w); p.Freeze(); return p; }

        FormattedText Txt(string s, double size, Brush b, bool bold)
        {
            var tf = new Typeface(new FontFamily("Segoe UI, Microsoft YaHei UI"), FontStyles.Normal, bold ? FontWeights.SemiBold : FontWeights.Normal, FontStretches.Normal);
            return new FormattedText(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, tf, size, b, VisualTreeHelper.GetDpi(this).PixelsPerDip);
        }

        static double Nice(double raw)
        {
            if (raw <= 0) return 1;
            double e = Math.Pow(10, Math.Floor(Math.Log10(raw))), f = raw / e;
            return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * e;
        }

        // 纵轴刻度统一按刻度步长决定小数位，避免出现“15 / 10 / 5.0”这种混排
        static string Axis(double v, double step)
        {
            int digits = step >= 1 ? 0 : (int)Math.Ceiling(-Math.Log10(step) - 1e-9);
            return v.ToString("F" + digits);
        }

        public static string Ms(double v) { return v < 10 ? v.ToString("0.0") : v < 1000 ? v.ToString("0") : v.ToString("#,0"); }

        protected override void OnRender(DrawingContext dc)
        {
            double W = ActualWidth, H = ActualHeight;
            dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, W, H));
            int total = Data.Count, start = Math.Max(0, total - Window), shown = total - start;
            int slots = Math.Max(shown, Planned > 0 && Planned <= Window ? Planned : shown);
            if (slots == 0)
            {
                var e = Txt("输入 IP 后按回车或点「开始测试」", 13, muted, false);
                dc.DrawText(e, new Point((W - e.Width) / 2, (H - e.Height) / 2));
                return;
            }

            double maxMs = 0;
            for (int i = start; i < total; i++) if (Data[i].Ok) maxMs = Math.Max(maxMs, Data[i].Ms);
            if (maxMs <= 0) maxMs = 10;
            double step = Nice(maxMs * 1.15 / 4), yMax = Math.Ceiling(maxMs * 1.15 / step) * step;

            double labelW = Txt(Axis(yMax, step), 11, muted, false).Width;
            double left = Math.Ceiling(labelW) + 10, right = W - 6, top = 8, bottom = H - 22;
            if (bottom - top < 20 || right - left < 20) return;
            Func<double, double> Y = v => bottom - v / yMax * (bottom - top);
            double xs = (right - left) / slots;
            Func<int, double> X = i => left + (i + 0.5) * xs;

            for (double v = step; v <= yMax + step / 2; v += step)
            {
                double y = Math.Round(Y(v)) + 0.5;
                dc.DrawLine(grid, new Point(left, y), new Point(right, y));
                var t = Txt(Axis(v, step), 11, muted, false);
                dc.DrawText(t, new Point(left - 8 - t.Width, y - t.Height / 2));
            }
            var z = Txt("0", 11, muted, false);
            dc.DrawText(z, new Point(left - 8 - z.Width, bottom - z.Height / 2));

            double bw = Math.Max(2, Math.Min(10, xs * 0.6));
            for (int i = 0; i < shown; i++)
                if (!Data[start + i].Ok) dc.DrawRectangle(lossBand, null, new Rect(X(i) - bw / 2, top, bw, bottom - top));

            // 连续成功的点连成一段；遇到丢包断开，不跨丢包连线
            int run = -1;
            for (int i = 0; i <= shown; i++)
            {
                bool ok = i < shown && Data[start + i].Ok;
                if (ok && run < 0) run = i;
                if (!ok && run >= 0)
                {
                    if (i - run >= 2)
                    {
                        var ag = new StreamGeometry();
                        using (var c = ag.Open())
                        {
                            c.BeginFigure(new Point(X(run), bottom), true, true);
                            for (int k = run; k < i; k++) c.LineTo(new Point(X(k), Y(Data[start + k].Ms)), false, false);
                            c.LineTo(new Point(X(i - 1), bottom), false, false);
                        }
                        dc.DrawGeometry(area, null, ag);
                        var lg = new StreamGeometry();
                        using (var c = lg.Open())
                        {
                            c.BeginFigure(new Point(X(run), Y(Data[start + run].Ms)), false, false);
                            for (int k = run + 1; k < i; k++) c.LineTo(new Point(X(k), Y(Data[start + k].Ms)), true, true);
                        }
                        dc.DrawGeometry(null, line, lg);
                    }
                    run = -1;
                }
            }
            dc.DrawLine(baseline, new Point(left, Math.Round(bottom) + 0.5), new Point(right, Math.Round(bottom) + 0.5));

            int lastOk = -1;
            for (int i = 0; i < shown; i++) if (Data[start + i].Ok) lastOk = i;
            for (int i = 0; i < shown; i++)
            {
                var d = Data[start + i];
                if (!d.Ok) continue;
                bool isolated = (i == 0 || !Data[start + i - 1].Ok) && (i == shown - 1 || !Data[start + i + 1].Ok);
                if (xs >= 10 || isolated || i == lastOk) dc.DrawEllipse(series, ring, new Point(X(i), Y(d.Ms)), 4, 4);
            }

            int every = (int)Math.Max(1, Nice(slots / 7.0));
            for (int i = 0; i < slots; i++)
            {
                int seq = start + i + 1;
                if (seq % every != 0 && i != 0) continue;
                var t = Txt(seq.ToString(), 11, muted, false);
                double x = Math.Max(left, Math.Min(right - t.Width, X(i) - t.Width / 2));
                if (i == 0 || seq % every == 0) dc.DrawText(t, new Point(x, bottom + 5));
            }

            if (hover >= 0 && hover < shown)
            {
                var d = Data[start + hover];
                double x = Math.Round(X(hover)) + 0.5;
                dc.DrawLine(cross, new Point(x, top), new Point(x, bottom));
                if (d.Ok) dc.DrawEllipse(series, ring, new Point(X(hover), Y(d.Ms)), 5, 5);
                var t1 = Txt("第 " + d.Seq + " 次", 11, ink2, false);
                var t2 = Txt(d.Ok ? Ms(d.Ms) + " ms" : d.Note, 13, ink, true);
                double w = Math.Max(t1.Width, t2.Width + (d.Ok ? 0 : 14)) + 20, h = t1.Height + t2.Height + 14;
                double bx = x + 12 + w > W ? x - 12 - w : x + 12, by = top + 4;
                dc.DrawRoundedRectangle(field, tipBorder, new Rect(bx, by, w, h), 6, 6);
                dc.DrawText(t1, new Point(bx + 10, by + 6));
                double tx = bx + 10;
                if (!d.Ok) { dc.DrawEllipse(critical, null, new Point(tx + 4, by + 8 + t1.Height + t2.Height / 2), 4, 4); tx += 14; }
                dc.DrawText(t2, new Point(tx, by + 8 + t1.Height));
            }
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            int total = Data.Count, start = Math.Max(0, total - Window), shown = total - start;
            int slots = Math.Max(shown, Planned > 0 && Planned <= Window ? Planned : shown);
            int h = -1;
            if (shown > 0)
            {
                double labelW = 40, left = labelW, right = ActualWidth - 6;
                // 与 OnRender 一致的左边距需要文字宽度；这里用近似值，只决定悬停到哪一个点
                double maxMs = 0;
                for (int i = start; i < total; i++) if (Data[i].Ok) maxMs = Math.Max(maxMs, Data[i].Ms);
                if (maxMs <= 0) maxMs = 10;
                double step = Nice(maxMs * 1.15 / 4), yMax = Math.Ceiling(maxMs * 1.15 / step) * step;
                left = Math.Ceiling(Txt(Axis(yMax, step), 11, muted, false).Width) + 10;
                double xs = (right - left) / slots;
                int i2 = (int)Math.Floor((e.GetPosition(this).X - left) / xs);
                if (i2 >= 0 && i2 < shown) h = i2;
            }
            if (h != hover) { hover = h; InvalidateVisual(); }
        }

        protected override void OnMouseLeave(MouseEventArgs e)
        {
            if (hover != -1) { hover = -1; InvalidateVisual(); }
        }
    }

    // ---------- 主窗口 ----------
    class MainWindow : Window
    {
        [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

        const string Xaml = @"
<Grid xmlns='http://schemas.microsoft.com/winfx/2006/xaml/presentation' xmlns:x='http://schemas.microsoft.com/winfx/2006/xaml'
      Background='$PAGE$' TextElement.FontFamily='Segoe UI, Microsoft YaHei UI' TextElement.FontSize='13' TextElement.Foreground='$INK$'>
 <Grid.Resources>
  <Style x:Key='Card' TargetType='Border'>
   <Setter Property='Background' Value='$SURFACE$'/><Setter Property='BorderBrush' Value='$BORDER$'/>
   <Setter Property='BorderThickness' Value='1'/><Setter Property='CornerRadius' Value='10'/><Setter Property='Padding' Value='16'/>
  </Style>
  <Style x:Key='Cap' TargetType='TextBlock'>
   <Setter Property='Foreground' Value='$MUTED$'/><Setter Property='FontSize' Value='12'/><Setter Property='Margin' Value='0,0,0,5'/>
  </Style>
  <Style x:Key='Val' TargetType='TextBlock'>
   <Setter Property='FontSize' Value='20'/><Setter Property='FontWeight' Value='SemiBold'/>
  </Style>
  <Style TargetType='TextBox'>
   <Setter Property='Foreground' Value='$INK$'/><Setter Property='CaretBrush' Value='$INK$'/><Setter Property='SelectionBrush' Value='$ACCENT$'/>
   <Setter Property='Background' Value='$FIELD$'/><Setter Property='BorderBrush' Value='$FIELDBORDER$'/><Setter Property='BorderThickness' Value='1'/>
   <Setter Property='Padding' Value='6,0'/><Setter Property='Height' Value='34'/><Setter Property='VerticalContentAlignment' Value='Center'/>
   <Setter Property='Template'><Setter.Value>
    <ControlTemplate TargetType='TextBox'>
     <Border x:Name='B' Background='{TemplateBinding Background}' BorderBrush='{TemplateBinding BorderBrush}' BorderThickness='{TemplateBinding BorderThickness}' CornerRadius='6'>
      <ScrollViewer x:Name='PART_ContentHost' Margin='{TemplateBinding Padding}' VerticalAlignment='{TemplateBinding VerticalContentAlignment}'/>
     </Border>
     <ControlTemplate.Triggers>
      <Trigger Property='IsKeyboardFocused' Value='True'><Setter TargetName='B' Property='BorderBrush' Value='$ACCENT$'/></Trigger>
      <Trigger Property='IsEnabled' Value='False'><Setter TargetName='B' Property='Opacity' Value='0.5'/></Trigger>
     </ControlTemplate.Triggers>
    </ControlTemplate>
   </Setter.Value></Setter>
  </Style>
  <Style x:Key='Primary' TargetType='Button'>
   <Setter Property='Foreground' Value='#FFFFFFFF'/><Setter Property='Background' Value='$ACCENT$'/><Setter Property='FontWeight' Value='SemiBold'/>
   <Setter Property='Padding' Value='22,0'/><Setter Property='Height' Value='34'/><Setter Property='Cursor' Value='Hand'/><Setter Property='Focusable' Value='False'/>
   <Setter Property='Template'><Setter.Value>
    <ControlTemplate TargetType='Button'>
     <Border x:Name='B' Background='{TemplateBinding Background}' CornerRadius='6' Padding='{TemplateBinding Padding}'>
      <ContentPresenter HorizontalAlignment='Center' VerticalAlignment='Center'/>
     </Border>
     <ControlTemplate.Triggers>
      <Trigger Property='IsMouseOver' Value='True'><Setter TargetName='B' Property='Opacity' Value='0.9'/></Trigger>
      <Trigger Property='IsPressed' Value='True'><Setter TargetName='B' Property='Opacity' Value='0.78'/></Trigger>
     </ControlTemplate.Triggers>
    </ControlTemplate>
   </Setter.Value></Setter>
  </Style>
  <Style x:Key='Ghost' TargetType='Button'>
   <Setter Property='Foreground' Value='$INK2$'/><Setter Property='Padding' Value='12,0'/><Setter Property='Height' Value='28'/>
   <Setter Property='FontSize' Value='12'/><Setter Property='Cursor' Value='Hand'/><Setter Property='Focusable' Value='False'/>
   <Setter Property='Template'><Setter.Value>
    <ControlTemplate TargetType='Button'>
     <Border x:Name='B' Background='Transparent' BorderBrush='$FIELDBORDER$' BorderThickness='1' CornerRadius='6' Padding='{TemplateBinding Padding}'>
      <ContentPresenter HorizontalAlignment='Center' VerticalAlignment='Center'/>
     </Border>
     <ControlTemplate.Triggers>
      <Trigger Property='IsMouseOver' Value='True'><Setter TargetName='B' Property='Background' Value='$WASH$'/></Trigger>
     </ControlTemplate.Triggers>
    </ControlTemplate>
   </Setter.Value></Setter>
  </Style>
  <Style x:Key='Pill' TargetType='RadioButton'>
   <Setter Property='Foreground' Value='$INK2$'/><Setter Property='Margin' Value='0,0,6,6'/><Setter Property='Cursor' Value='Hand'/><Setter Property='Focusable' Value='False'/>
   <Setter Property='Template'><Setter.Value>
    <ControlTemplate TargetType='RadioButton'>
     <Border x:Name='B' Background='$FIELD$' BorderBrush='$FIELDBORDER$' BorderThickness='1' CornerRadius='6' Padding='12,0' MinHeight='34'>
      <ContentPresenter VerticalAlignment='Center'/>
     </Border>
     <ControlTemplate.Triggers>
      <Trigger Property='IsMouseOver' Value='True'><Setter TargetName='B' Property='BorderBrush' Value='$MUTED$'/></Trigger>
      <Trigger Property='IsChecked' Value='True'>
       <Setter TargetName='B' Property='Background' Value='$WASH$'/><Setter TargetName='B' Property='BorderBrush' Value='$ACCENT$'/>
       <Setter Property='Foreground' Value='$INK$'/>
      </Trigger>
      <Trigger Property='IsEnabled' Value='False'><Setter TargetName='B' Property='Opacity' Value='0.5'/></Trigger>
     </ControlTemplate.Triggers>
    </ControlTemplate>
   </Setter.Value></Setter>
  </Style>
  <Style TargetType='ScrollBar'>
   <Style.Triggers>
    <Trigger Property='Orientation' Value='Vertical'>
     <Setter Property='Width' Value='8'/><Setter Property='MinWidth' Value='8'/>
     <Setter Property='Template'><Setter.Value>
      <ControlTemplate TargetType='ScrollBar'>
       <Track x:Name='PART_Track' IsDirectionReversed='True'>
        <Track.Thumb><Thumb><Thumb.Template><ControlTemplate TargetType='Thumb'><Border Background='$SCROLL$' CornerRadius='4'/></ControlTemplate></Thumb.Template></Thumb></Track.Thumb>
       </Track>
      </ControlTemplate>
     </Setter.Value></Setter>
    </Trigger>
    <Trigger Property='Orientation' Value='Horizontal'>
     <Setter Property='Height' Value='8'/><Setter Property='MinHeight' Value='8'/>
     <Setter Property='Template'><Setter.Value>
      <ControlTemplate TargetType='ScrollBar'>
       <Track x:Name='PART_Track'>
        <Track.Thumb><Thumb><Thumb.Template><ControlTemplate TargetType='Thumb'><Border Background='$SCROLL$' CornerRadius='4'/></ControlTemplate></Thumb.Template></Thumb></Track.Thumb>
       </Track>
      </ControlTemplate>
     </Setter.Value></Setter>
    </Trigger>
   </Style.Triggers>
  </Style>
 </Grid.Resources>

 <Grid Margin='18'>
  <Grid.RowDefinitions>
   <RowDefinition Height='Auto'/><RowDefinition Height='Auto'/><RowDefinition Height='*' MinHeight='170'/><RowDefinition x:Name='RLog' Height='170'/>
  </Grid.RowDefinitions>

  <Border Style='{StaticResource Card}'>
   <StackPanel>
    <Grid>
     <Grid.ColumnDefinitions>
      <ColumnDefinition Width='*'/><ColumnDefinition Width='Auto'/><ColumnDefinition Width='Auto'/><ColumnDefinition Width='Auto'/>
     </Grid.ColumnDefinitions>
     <StackPanel Margin='0,0,14,0'>
      <TextBlock Style='{StaticResource Cap}' Text='目标 IP 或域名'/>
      <TextBox x:Name='TTarget' FontSize='15'/>
     </StackPanel>
     <StackPanel Grid.Column='1' Margin='0,0,14,0'>
      <TextBlock Style='{StaticResource Cap}' Text='测试方式'/>
      <StackPanel Orientation='Horizontal'>
       <RadioButton x:Name='RIcmp' GroupName='mode' Style='{StaticResource Pill}' Content='ICMP Ping' IsChecked='True' Margin='0,0,6,0'/>
       <RadioButton x:Name='RTcp' GroupName='mode' Style='{StaticResource Pill}' Content='TCP 连接' Margin='0,0,6,0'/>
       <RadioButton x:Name='RTrace' GroupName='mode' Style='{StaticResource Pill}' Content='路由追踪' Margin='0'/>
      </StackPanel>
     </StackPanel>
     <StackPanel Grid.Column='2' Margin='0,0,14,0'>
      <TextBlock Style='{StaticResource Cap}' Text='TCP 端口'/>
      <TextBox x:Name='TPort' Width='72' Text='443'/>
     </StackPanel>
     <Button x:Name='BStart' Grid.Column='3' Style='{StaticResource Primary}' Content='开始测试' VerticalAlignment='Bottom' MinWidth='112'/>
    </Grid>
    <WrapPanel Margin='0,14,0,0'>
     <StackPanel Margin='0,0,14,0'><TextBlock Style='{StaticResource Cap}' Text='次数（0 = 一直测）'/><TextBox x:Name='TCount' Width='118' Text='20'/></StackPanel>
     <StackPanel Margin='0,0,14,0'><TextBlock Style='{StaticResource Cap}' Text='间隔（毫秒）'/><TextBox x:Name='TInterval' Width='118' Text='1000'/></StackPanel>
     <StackPanel Margin='0,0,14,0'><TextBlock Style='{StaticResource Cap}' Text='超时（毫秒）'/><TextBox x:Name='TTimeout' Width='118' Text='2000'/></StackPanel>
     <StackPanel Margin='0,0,14,0'><TextBlock Style='{StaticResource Cap}' Text='Ping 包大小（字节）'/><TextBox x:Name='TSize' Width='118' Text='32'/></StackPanel>
    </WrapPanel>
    <TextBlock Style='{StaticResource Cap}' Text='从哪张网卡发出' Margin='0,14,0,5'/>
    <WrapPanel x:Name='WNics'/>
    <TextBlock x:Name='TNicHint' Foreground='$INK2$' FontSize='12' TextWrapping='Wrap' Margin='0,2,0,0'/>
   </StackPanel>
  </Border>

  <Border Grid.Row='1' Style='{StaticResource Card}' Margin='0,12,0,0'>
   <StackPanel>
    <Grid>
     <Grid.ColumnDefinitions><ColumnDefinition Width='Auto'/><ColumnDefinition Width='*'/></Grid.ColumnDefinitions>
     <StackPanel Margin='0,0,32,0' MinWidth='150'>
      <TextBlock Style='{StaticResource Cap}' Text='平均延迟'/>
      <StackPanel Orientation='Horizontal'>
       <TextBlock x:Name='VAvg' Text='—' FontSize='44' FontWeight='SemiBold'/>
       <TextBlock Text='ms' FontSize='16' Foreground='$INK2$' VerticalAlignment='Bottom' Margin='6,0,0,10'/>
      </StackPanel>
     </StackPanel>
     <UniformGrid Grid.Column='1' Rows='1' VerticalAlignment='Center'>
      <StackPanel>
       <TextBlock Style='{StaticResource Cap}' Text='丢包率'/>
       <StackPanel Orientation='Horizontal'>
        <Ellipse x:Name='LossDot' Width='9' Height='9' Fill='$MUTED$' Margin='0,0,7,0' VerticalAlignment='Center'/>
        <TextBlock x:Name='VLoss' Style='{StaticResource Val}' Text='—'/>
       </StackPanel>
      </StackPanel>
      <StackPanel><TextBlock Style='{StaticResource Cap}' Text='最小'/><TextBlock x:Name='VMin' Style='{StaticResource Val}' Text='—'/></StackPanel>
      <StackPanel><TextBlock Style='{StaticResource Cap}' Text='最大'/><TextBlock x:Name='VMax' Style='{StaticResource Val}' Text='—'/></StackPanel>
      <StackPanel><TextBlock Style='{StaticResource Cap}' Text='抖动'/><TextBlock x:Name='VJit' Style='{StaticResource Val}' Text='—'/></StackPanel>
      <StackPanel><TextBlock Style='{StaticResource Cap}' Text='已收 / 已发'/><TextBlock x:Name='VCount' Style='{StaticResource Val}' Text='—'/></StackPanel>
     </UniformGrid>
    </Grid>
    <StackPanel Orientation='Horizontal' Margin='0,12,0,0'>
     <Ellipse x:Name='StatusDot' Width='8' Height='8' Fill='$MUTED$' Margin='0,0,8,0' VerticalAlignment='Center'/>
     <TextBlock x:Name='TStatus' Foreground='$INK2$' FontSize='12' TextWrapping='Wrap' Text='就绪'/>
    </StackPanel>
   </StackPanel>
  </Border>

  <Border Grid.Row='2' Style='{StaticResource Card}' Margin='0,12,0,0' Padding='16,12,16,10'>
   <Grid>
    <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/></Grid.RowDefinitions>
    <DockPanel>
     <StackPanel x:Name='PLegend' DockPanel.Dock='Right' Orientation='Horizontal' VerticalAlignment='Center'>
      <Rectangle Width='6' Height='12' Fill='$LOSSBAND$' Margin='0,0,6,0'/>
      <TextBlock Text='丢包 / 超时' Foreground='$MUTED$' FontSize='12'/>
     </StackPanel>
     <TextBlock x:Name='TChartTitle' Text='延迟走势（ms）' FontWeight='SemiBold'/>
    </DockPanel>
    <ContentControl x:Name='ChartHost' Grid.Row='1' Margin='0,8,0,0' Focusable='False'/>
   </Grid>
  </Border>

  <Border Grid.Row='3' Style='{StaticResource Card}' Margin='0,12,0,0' Padding='16,10,10,10'>
   <Grid>
    <Grid.RowDefinitions><RowDefinition Height='Auto'/><RowDefinition Height='*'/></Grid.RowDefinitions>
    <DockPanel Margin='0,0,6,0'>
     <Button x:Name='BCopy' DockPanel.Dock='Right' Style='{StaticResource Ghost}' Content='复制结果'/>
     <TextBlock Text='逐次结果' FontWeight='SemiBold' VerticalAlignment='Center'/>
    </DockPanel>
    <TextBox x:Name='TLog' Grid.Row='1' Margin='0,6,0,0' IsReadOnly='True' BorderThickness='0' Background='Transparent' Padding='0' Height='Auto'
             VerticalContentAlignment='Stretch' TextWrapping='Wrap' VerticalScrollBarVisibility='Auto' HorizontalScrollBarVisibility='Disabled'
             FontFamily='Consolas, Microsoft YaHei UI' FontSize='12' Foreground='$INK2$'/>
   </Grid>
  </Border>
 </Grid>
</Grid>";

        readonly Theme th;
        readonly FrameworkElement root;
        readonly TextBox tTarget, tPort, tCount, tInterval, tTimeout, tSize, tLog;
        readonly RadioButton rIcmp, rTcp, rTrace;
        readonly Button bStart, bCopy;
        readonly WrapPanel wNics;
        readonly TextBlock tNicHint, vAvg, vLoss, vMin, vMax, vJit, vCount, tStatus, tChartTitle;
        readonly Ellipse lossDot, statusDot;
        readonly LatencyChart chart;
        readonly HopTable hopTable;
        readonly ScrollViewer hopScroll;
        readonly ContentControl chartHost;
        readonly FrameworkElement pLegend;
        readonly RowDefinition rLog;
        readonly List<RadioButton> nicButtons = new List<RadioButton>();
        List<Nic> nics = new List<Nic>();

        ManualResetEvent stopEvt;
        bool running, followEnd = true;
        Settings cur;
        string pathText = "", portHint;
        int sent, recv, jitN;
        double sum, min, max, jitSum, lastOk = -1;

        T F<T>(string name) where T : class { return root.FindName(name) as T; }

        public MainWindow()
        {
            th = Theme.Detect();
#if SHOT
            IpMask.Mask = Environment.GetCommandLineArgs().Contains("mask");
#endif
            Title = "IP 质量测试 1.1.0";
            Width = 960; Height = 860; MinWidth = 800; MinHeight = 720;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            UseLayoutRounding = true;
            Background = Theme.B(th.Page);

            string x = Xaml
                .Replace("$PAGE$", Theme.Hex(th.Page)).Replace("$SURFACE$", Theme.Hex(th.Surface)).Replace("$BORDER$", Theme.Hex(th.Border))
                .Replace("$INK$", Theme.Hex(th.Ink)).Replace("$INK2$", Theme.Hex(th.Ink2)).Replace("$MUTED$", Theme.Hex(th.Muted))
                .Replace("$FIELD$", Theme.Hex(th.Field)).Replace("$FIELDBORDER$", Theme.Hex(th.FieldBorder))
                .Replace("$ACCENT$", Theme.Hex(th.Accent)).Replace("$WASH$", Theme.Hex(th.Wash)).Replace("$SCROLL$", Theme.Hex(th.Scroll))
                .Replace("$LOSSBAND$", Theme.Hex(Color.FromArgb(56, th.Critical.R, th.Critical.G, th.Critical.B)));
            root = (FrameworkElement)XamlReader.Parse(x);
            Content = root;

            tTarget = F<TextBox>("TTarget"); tPort = F<TextBox>("TPort"); tCount = F<TextBox>("TCount");
            tInterval = F<TextBox>("TInterval"); tTimeout = F<TextBox>("TTimeout"); tSize = F<TextBox>("TSize"); tLog = F<TextBox>("TLog");
            rIcmp = F<RadioButton>("RIcmp"); rTcp = F<RadioButton>("RTcp"); rTrace = F<RadioButton>("RTrace");
            tChartTitle = F<TextBlock>("TChartTitle"); pLegend = F<FrameworkElement>("PLegend"); rLog = F<RowDefinition>("RLog");
            bStart = F<Button>("BStart"); bCopy = F<Button>("BCopy");
            wNics = F<WrapPanel>("WNics"); tNicHint = F<TextBlock>("TNicHint");
            vAvg = F<TextBlock>("VAvg"); vLoss = F<TextBlock>("VLoss"); vMin = F<TextBlock>("VMin");
            vMax = F<TextBlock>("VMax"); vJit = F<TextBlock>("VJit"); vCount = F<TextBlock>("VCount");
            tStatus = F<TextBlock>("TStatus"); lossDot = F<Ellipse>("LossDot"); statusDot = F<Ellipse>("StatusDot");
            chart = new LatencyChart(th);
            hopTable = new HopTable(th);
            hopScroll = new ScrollViewer { Content = hopTable, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                                           HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, Focusable = false };
            hopTable.Host = hopScroll;
            // 用户往上翻就不再自动跟随；翻回底部恢复跟随
            hopScroll.ScrollChanged += (o, e) =>
            {
                if (e.ExtentHeightChange == 0 && e.ViewportHeightChange == 0 && e.VerticalChange != 0)
                    followEnd = hopScroll.VerticalOffset >= hopScroll.ScrollableHeight - 2;
                if (e.VerticalChange != 0) hopTable.InvalidateVisual();
            };
            chartHost = F<ContentControl>("ChartHost");
            chartHost.Content = chart;

            bStart.Click += delegate { if (running) Stop(); else Start(); };
            bCopy.Click += delegate { Copy(); };
            rIcmp.Checked += delegate { ModeChanged(); };
            rTcp.Checked += delegate { ModeChanged(); };
            rTrace.Checked += delegate { ModeChanged(); };
            PreviewKeyDown += OnKey;
            SourceInitialized += delegate
            {
                if (!th.Dark) return;
                int on = 1;
                try { DwmSetWindowAttribute(new WindowInteropHelper(this).Handle, 20, ref on, 4); } catch { }
            };
            Loaded += delegate { tTarget.Focus(); };
#if SHOT
            // 仅测试版：IPQuality.exe 截图.png 目标 秒数 [icmp] —— 自动开始、到时截图并把日志写到 .txt，然后退出
            Loaded += delegate
            {
                var a = Environment.GetCommandLineArgs();
                if (a.Length < 4) return;
                tTarget.Text = a[2]; tCount.Text = "0";
                if (a.Length >= 5 && a[4] == "icmp") rIcmp.IsChecked = true; else rTrace.IsChecked = true;
                if (a.Length >= 6) Width = int.Parse(a[5]);
                Start();
                var timer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(int.Parse(a[3])) };
                timer.Tick += delegate
                {
                    timer.Stop();
                    var c = (FrameworkElement)Content;
                    var bmp = new System.Windows.Media.Imaging.RenderTargetBitmap((int)c.ActualWidth, (int)c.ActualHeight, 96, 96, PixelFormats.Pbgra32);
                    bmp.Render(c);
                    var enc = new System.Windows.Media.Imaging.PngBitmapEncoder();
                    enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bmp));
                    using (var f = System.IO.File.Create(a[1])) enc.Save(f);
                    System.IO.File.WriteAllText(a[1] + ".txt", tLog.Text + "\r\n" + hopTable.Text(), Encoding.UTF8);
                    Close();
                };
                timer.Start();
            };
#endif

            LoadNicButtons();
            ModeChanged();
        }

        void LoadNicButtons()
        {
            try { nics = Net.LoadNics(); } catch { nics = new List<Nic>(); }
            wNics.Children.Clear(); nicButtons.Clear();
            var pill = (Style)root.FindResource("Pill");
            foreach (var n in nics)
            {
                string text = n.Name + " · " + IpMask.Ip(n.Ip) + (n.Virtual ? "（虚拟网卡）" : "");
                var rb = new RadioButton { Style = pill, GroupName = "nic", Content = text, Tag = n, ToolTip = n.Desc };
                rb.Checked += delegate { NicChanged(); };
                wNics.Children.Add(rb); nicButtons.Add(rb);
            }
            var sys = new RadioButton { Style = pill, GroupName = "nic", Content = "不指定（按系统路由）", Tag = null };
            sys.Checked += delegate { NicChanged(); };
            wNics.Children.Add(sys); nicButtons.Add(sys);
            var best = nicButtons.FirstOrDefault(b => b.Tag != null && !((Nic)b.Tag).Virtual);
            (best ?? sys).IsChecked = true;
            NicChanged();
        }

        Nic SelectedNic()
        {
            var b = nicButtons.FirstOrDefault(r => r.IsChecked == true);
            return b == null ? null : b.Tag as Nic;
        }

        void NicChanged()
        {
            var n = SelectedNic();
            if (n == null)
                tNicHint.Text = "按 Windows 路由表发出。v2rayN 开着 TUN 时会被它接管，TCP 结果只是本机到 v2rayN 的时间，不可信。";
            else if (n.Virtual)
                tNicHint.Text = "这是虚拟网卡（代理或隧道），测到的是走这条隧道的结果，不是本机直连。";
            else
                tNicHint.Text = "测试包从「" + n.Name + "」直接发出，不经过 v2rayN（TUN 模式也绕得开）；域名经这张网卡用阿里 DNS（HTTPS）解析。";
        }

        void ModeChanged()
        {
            bool tcp = rTcp.IsChecked == true, trace = rTrace.IsChecked == true;
            tPort.IsEnabled = tcp && !running;
            tSize.IsEnabled = !tcp && !running;
            if (chartHost == null) return;
            chartHost.Content = trace ? (object)hopScroll : chart;
            tChartTitle.Text = trace ? "逐跳路由（每一跳的丢包与延迟）" : "延迟走势（ms）";
            pLegend.Visibility = trace ? Visibility.Collapsed : Visibility.Visible;
            rLog.Height = new GridLength(trace ? 96 : 170);
            if (trace && IsLoaded && Height < 1040) Height = Math.Min(1040, SystemParameters.WorkArea.Height);
        }

        void OnKey(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && !running) { Start(); e.Handled = true; }
            else if (e.Key == Key.Escape && running) { Stop(); e.Handled = true; }
        }

        void SetStatus(string text, Color dot)
        {
            tStatus.Text = text;
            statusDot.Fill = Theme.B(dot);
        }

        bool ReadInt(TextBox t, string name, int lo, int hi, out int v)
        {
            if (int.TryParse(t.Text.Trim(), out v) && v >= lo && v <= hi) return true;
            SetStatus(name + "要填 " + lo + " 到 " + hi + " 之间的整数", th.Critical);
            t.Focus(); t.SelectAll();
            return false;
        }

        void Start()
        {
            var s = new Settings();
            string target = tTarget.Text.Trim();
            if (target.Length == 0) { SetStatus("先填要测的 IP 或域名", th.Critical); tTarget.Focus(); return; }

            // 支持直接粘贴 “IP:端口”，自动切到 TCP
            var m = Regex.Match(target, @"^([^:\s]+):(\d{1,5})$");
            if (m.Success)
            {
                target = m.Groups[1].Value; tTarget.Text = target;
                if (rTrace.IsChecked != true) { tPort.Text = m.Groups[2].Value; rTcp.IsChecked = true; }
            }
            if (target.Contains(":")) { SetStatus("只支持 IPv4", th.Critical); return; }

            s.TargetText = target;
            s.Tcp = rTcp.IsChecked == true;
            s.Trace = rTrace.IsChecked == true;
            s.Source = SelectedNic();
            int v;
            if (!ReadInt(tCount, "次数", 0, 1000000, out v)) return; s.Count = v;
            if (!ReadInt(tInterval, "间隔", s.Trace ? 500 : 100, 600000, out v)) return; s.Interval = v;
            if (!ReadInt(tTimeout, "超时", 100, 60000, out v)) return; s.Timeout = v;
            if (s.Tcp) { if (!ReadInt(tPort, "端口", 1, 65535, out v)) return; s.Port = v; }
            else { if (!ReadInt(tSize, "包大小", 0, 65500, out v)) return; s.Size = v; }

            cur = s;
            portHint = null;
            sent = recv = jitN = 0; sum = jitSum = 0; min = double.MaxValue; max = 0; lastOk = -1;
            chart.Data = new List<Probe>(); chart.Planned = s.Count; chart.InvalidateVisual();
            hopTable.State = null; hopTable.InvalidateMeasure(); hopTable.InvalidateVisual();
            followEnd = true;
            tLog.Clear();
            UpdateStats();
            SetRunning(true);
            SetStatus("正在解析 " + target + " …", th.Accent);

            stopEvt = new ManualResetEvent(false);
            var stop = stopEvt;
            var t = new Thread(() => Work(s, stop));
            t.IsBackground = true;
            t.Start();
        }

        void Stop()
        {
            if (stopEvt != null) stopEvt.Set();
        }

        void SetRunning(bool on)
        {
            running = on;
            bStart.Content = on ? "停止" : "开始测试";
            bStart.Background = Theme.B(on ? th.Critical : th.Accent);
            foreach (var c in new UIElement[] { tTarget, tCount, tInterval, tTimeout, rIcmp, rTcp, rTrace }) c.IsEnabled = !on;
            foreach (var b in nicButtons) b.IsEnabled = !on;
            ModeChanged();
        }

        void Ui(Action a) { Dispatcher.BeginInvoke(a); }

        void Work(Settings s, ManualResetEvent stop)
        {
            Icmp icmp = null;
            try
            {
                IPAddress ip;
                string via = null;
                if (Regex.IsMatch(s.TargetText, @"^\d{1,3}(\.\d{1,3}){3}$"))
                {
                    if (!IPAddress.TryParse(s.TargetText, out ip)) throw new Exception("IP 格式不对");
                }
                else ip = Net.Resolve(s.TargetText, s.Source, out via);
                s.Target = ip;

                var b = ip.GetAddressBytes();
                bool fake = b[0] == 198 && (b[1] == 18 || b[1] == 19);
                string from = s.Source == null ? "本机（系统路由）" : "本机 " + IpMask.Ip(s.Source.Ip) + "（" + s.Source.Name + "）";
                string to = via == null ? ip.ToString() : s.TargetText + "（" + ip + "，经 " + via + " 解析）";
                string mode = s.Trace ? "路由追踪（ICMP " + s.Size + " 字节）" : s.Tcp ? "TCP " + s.Port : "ICMP " + s.Size + " 字节";
                string route = s.Source == null ? "可能经过 v2rayN" : s.Source.Virtual ? "走虚拟网卡" : "绕过 v2rayN";
                string path = from + " → " + to + " · " + mode + " · " + route;
                Ui(() =>
                {
                    pathText = path;
                    SetStatus(fake ? path + "。注意：这是 v2rayN 的虚拟地址（fake-ip），结果不代表真实服务器" : path, fake ? th.Warning : th.Accent);
                    Log("开始 " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + path);
                });

                if (s.Trace) { TraceLoop(s, stop, ip); return; }
                if (!s.Tcp) icmp = new Icmp(s.Size);
                var clock = Stopwatch.StartNew();
                for (int i = 1; s.Count == 0 || i <= s.Count; i++)
                {
                    if (stop.WaitOne(0)) break;
                    double t0 = clock.Elapsed.TotalMilliseconds;
                    var r = s.Tcp ? Net.Tcp(ip, s.Port, s.Source, s.Timeout) : icmp.Send(ip, s.Source, s.Timeout);
                    r.Seq = i;
                    Ui(() => Add(r));
                    if (s.Count != 0 && i == s.Count) break;
                    double wait = s.Interval - (clock.Elapsed.TotalMilliseconds - t0);
                    if (wait > 0 && stop.WaitOne((int)wait)) break;
                }
                bool stopped = stop.WaitOne(0);
                Ui(() => Finish(stopped ? "已停止" : "完成", null));
            }
            catch (Exception e)
            {
                string msg = e.Message;
                Ui(() => Finish(null, msg));
            }
            finally
            {
                if (icmp != null) icmp.Dispose();
            }
        }

        void TraceLoop(Settings s, ManualResetEvent stop, IPAddress ip)
        {
            var st = new TraceState();
            Ui(() => { hopTable.State = st; hopTable.InvalidateMeasure(); hopTable.InvalidateVisual(); });
            bool warned = false;
            using (var tr = new TraceIcmp(s.Size))
            {
                var clock = Stopwatch.StartNew();
                for (int i = 1; s.Count == 0 || i <= s.Count; i++)
                {
                    if (stop.WaitOne(0)) break;
                    double t0 = clock.Elapsed.TotalMilliseconds;
                    int upto = st.Dest > 0 ? st.Dest : TraceIcmp.MaxHops;
                    var res = tr.Round(ip, s.Source, upto, s.Timeout);
                    var target = new Probe { Seq = i, Note = "终点没有回应" };
                    var ask = new List<Hop>();
                    lock (st)
                    {
                        for (int t = 1; t <= upto; t++)
                        {
                            var hp = st.Get(t);
                            var r = res[t];
                            hp.Sent++;
                            hp.Hist.Add(r.Got);
                            if (hp.Hist.Count > HopTable.HistMax) hp.Hist.RemoveAt(0);
                            if (!r.Got) continue;
                            hp.Recv++; hp.Last = r.Ms; hp.Sum += r.Ms; hp.Min = Math.Min(hp.Min, r.Ms); hp.Max = Math.Max(hp.Max, r.Ms);
                            if (hp.Ip == null || !hp.Ip.Equals(r.From)) { hp.Ip = r.From; hp.Loc = Geo.Local(r.From); hp.LocTries = 0; }
                            st.MaxSeen = Math.Max(st.MaxSeen, t);
                            if (r.Status == 0 && r.From.Equals(ip) && (st.Dest == 0 || t < st.Dest)) st.Dest = t;
                        }
                        if (st.Dest > 0)
                        {
                            if (st.Hops.Count > st.Dest) st.Hops.RemoveRange(st.Dest, st.Hops.Count - st.Dest);
                            // 这一轮只要目标在任一 TTL 上回了 echo，就算终点收到（取最小的那一跳）
                            for (int t = st.Dest; t <= upto; t++)
                                if (res[t].Got && res[t].Status == 0 && res[t].From.Equals(ip))
                                { target.Ok = true; target.Ms = res[t].Ms; target.Note = "第 " + st.Dest + " 跳到达"; break; }
                        }
                        if (!st.GeoBusy)
                            ask = st.Hops.Where(h => h.Ip != null && h.Loc == null && h.LocTries < 3).ToList();
                        if (ask.Count > 0) st.GeoBusy = true;
                    }
                    if (ask.Count > 0)
                        ThreadPool.QueueUserWorkItem(delegate
                        {
                            Dictionary<string, string> got = null;
                            try { got = Geo.Lookup(ask.Select(h => h.Ip.ToString()).Distinct().ToList()); } catch { }
                            lock (st)
                            {
                                foreach (var h in ask)
                                {
                                    h.LocTries++;
                                    string v;
                                    if (got != null && got.TryGetValue(h.Ip.ToString(), out v)) h.Loc = v;
                                    else if (h.LocTries >= 3) h.Loc = "";
                                }
                                st.GeoBusy = false;
                            }
                            Ui(() => { hopTable.InvalidateMeasure(); hopTable.InvalidateVisual(); });
                        });
                    bool warn = !warned && i >= 3 && st.Dest == 0;
                    if (warn) warned = true;
                    Ui(() =>
                    {
                        Add(target);
                        // 默认跟随到底，保证终点那一行看得见；用户往上翻了就不打扰
                        hopTable.InvalidateMeasure(); hopTable.InvalidateVisual();
                        if (followEnd) Dispatcher.BeginInvoke(new Action(() => hopScroll.ScrollToEnd()), System.Windows.Threading.DispatcherPriority.Background);
                        if (warn) SetStatus("还没到达终点：目标可能禁 ping，表里只看得到中间各跳", th.Warning);
                    });
                    if (s.Count != 0 && i == s.Count) break;
                    double wait = s.Interval - (clock.Elapsed.TotalMilliseconds - t0);
                    if (wait > 0 && stop.WaitOne((int)wait)) break;
                }
            }
            bool stopped = stop.WaitOne(0);
            Ui(() => Finish(stopped ? "已停止" : "完成", null));
        }

        void Add(Probe r)
        {
            if (cur == null) return;
            sent++;
            if (r.Ok)
            {
                recv++; sum += r.Ms; min = Math.Min(min, r.Ms); max = Math.Max(max, r.Ms);
                if (lastOk >= 0) { jitSum += Math.Abs(r.Ms - lastOk); jitN++; }
                lastOk = r.Ms;
            }
            chart.Data.Add(r);
            chart.InvalidateVisual();
            UpdateStats();
            string line = string.Format("#{0,-5} {1}", r.Seq,
                r.Ok ? LatencyChart.Ms(r.Ms).PadLeft(6) + " ms  " + r.Note : "  ——    " + r.Note);
            Log(line);

            // TCP 第一次失败时提示原因：最常见的是端口没开放，或 NAT 机器填了内部端口而不是映射后的公网端口
            if (cur.Tcp && !r.Ok && portHint == null && (r.Note == "超时" || r.Note == "端口拒绝连接"))
            {
                portHint = r.Note == "超时"
                    ? "TCP " + cur.Port + " 连不上：这个端口可能没开放或被防火墙挡了；NAT 机器要填映射后的公网端口，也可以改用 ICMP Ping 试试"
                    : "TCP " + cur.Port + " 被拒绝：服务器在线，但这个端口没有程序在监听，请核对端口";
                Log("提示：" + portHint);
                SetStatus(portHint, th.Warning);
            }
        }

        void Log(string line)
        {
            if (tLog.Text.Length > 300000) tLog.Text = tLog.Text.Substring(tLog.Text.Length - 200000);
            tLog.AppendText((tLog.Text.Length == 0 ? "" : "\r\n") + line);
            tLog.ScrollToEnd();
        }

        void UpdateStats()
        {
            if (sent == 0)
            {
                vAvg.Text = vLoss.Text = vMin.Text = vMax.Text = vJit.Text = vCount.Text = "—";
                lossDot.Fill = Theme.B(th.Muted);
                return;
            }
            double loss = (sent - recv) * 100.0 / sent;
            vLoss.Text = loss.ToString(loss == 0 || loss == 100 ? "0" : "0.0") + "%";
            lossDot.Fill = Theme.B(loss == 0 ? th.Good : loss < 5 ? th.Warning : th.Critical);
            vCount.Text = recv + " / " + sent;
            vAvg.Text = recv > 0 ? LatencyChart.Ms(sum / recv) : "—";
            vMin.Text = recv > 0 ? LatencyChart.Ms(min) + " ms" : "—";
            vMax.Text = recv > 0 ? LatencyChart.Ms(max) + " ms" : "—";
            vJit.Text = jitN > 0 ? LatencyChart.Ms(jitSum / jitN) + " ms" : "—";
        }

        string Summary()
        {
            if (sent == 0) return "";
            return string.Format("统计：已发 {0}，已收 {1}，丢包 {2}；最小 {3} / 平均 {4} / 最大 {5} / 抖动 {6}",
                sent, recv, vLoss.Text, vMin.Text, recv > 0 ? vAvg.Text + " ms" : "—", vMax.Text, vJit.Text);
        }

        void Finish(string word, string error)
        {
            SetRunning(false);
            if (error != null)
            {
                SetStatus(error, th.Critical);
                Log("出错：" + error);
                return;
            }
            if (cur != null && cur.Trace && hopTable.State != null) Log("逐跳结果：\r\n" + hopTable.Text());
            if (sent > 0) Log((cur != null && cur.Trace ? "终点" : "") + Summary());
            double loss = sent == 0 ? 0 : (sent - recv) * 100.0 / sent;
            if (portHint != null && recv == 0) SetStatus(word + " · " + portHint, th.Critical);
            else SetStatus(word + " · " + pathText, sent > 0 && recv == 0 ? th.Critical : loss > 0 ? th.Warning : th.Good);
        }

        void Copy()
        {
            string text = tLog.Text;
            if (text.Length == 0) { SetStatus("还没有结果可复制", th.Muted); return; }
            if (running && cur != null && cur.Trace && hopTable.State != null) text += "\r\n逐跳结果：\r\n" + hopTable.Text();
            if (running && sent > 0) text += "\r\n" + Summary();
            try { Clipboard.SetText(text); SetStatus("结果已复制到剪贴板", th.Good); }
            catch { SetStatus("剪贴板被占用，稍后再试", th.Warning); }
        }

        protected override void OnClosed(EventArgs e)
        {
            Stop();
            base.OnClosed(e);
            Environment.Exit(0);
        }
    }
}
