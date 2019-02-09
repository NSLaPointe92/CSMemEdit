using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace CSMemEdit
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                var mem = new Memory(Process.GetCurrentProcess().Id);
                var modHandle = mem.GetProcessModuleHandle("CSMemEdit.exe");

                if (modHandle == IntPtr.Zero)
                    Console.WriteLine("ERROR: Failed to get module handle.");

                Win32.MODULEINFO mi = new Win32.MODULEINFO();
                var result = Win32.GetModuleInformation(mem.GetProcessHandle(), modHandle, out mi, (uint)Marshal.SizeOf(mi));

                if (!result)
                    Console.WriteLine("ERROR: " + Marshal.GetLastWin32Error().ToString());

                Console.WriteLine("Memory ranges from 0x{0} to 0x{1}.", mi.lpBaseOfDll.ToString("X8"), ((uint)mi.lpBaseOfDll + mi.SizeOfImage).ToString("X8"));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.ReadLine();
        }
    }
}
