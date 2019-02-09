using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CSMemEdit
{
    class Memory
    {
        private IntPtr proc { get; set; }

        public Memory() { }

        public Memory(int procId)
        {
            this.proc = Win32.OpenProcess(Win32.ProcessAccessRights.PROCESS_ALL_ACCESS, false, procId);
            if (this.proc == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == 5)
                    throw new Exception(string.Format("ERROR: {0} try running as admin.", error));
                else
                    throw new Exception(string.Format("ERROR: {0}", error));
            }
        }

        ~Memory()
        {
            Win32.CloseHandle(this.proc);
        }

        public IntPtr GetProcessHandle()
        {
            return proc;
        }

        public IntPtr GetProcessModuleHandle(string moduleName)
        {
            var hMods = new IntPtr[1024];

            var gch = GCHandle.Alloc(hMods, GCHandleType.Pinned);
            var pModules = gch.AddrOfPinnedObject();

            var uiSize = (uint)(Marshal.SizeOf(typeof(IntPtr)) * (hMods.Length));

            if (Win32.EnumProcessModules(proc, pModules, uiSize, out uint cbNeeded) == 1)
            {
                var uiTotalNumberofModules = (Int32)(cbNeeded / (Marshal.SizeOf(typeof(IntPtr))));

                for (var i = 0; i < (int)uiTotalNumberofModules; ++i)
                {
                    var stringBuilder = new StringBuilder(1024);

                    Win32.GetModuleFileNameEx(proc, hMods[i], stringBuilder, (uint)(stringBuilder.Capacity));
                    if (Path.GetFileName(stringBuilder.ToString().ToLower()) == moduleName.ToLower())
                        return hMods[i];
                }
            }

            gch.Free();

            return IntPtr.Zero;
        }

        public byte[] ReadProcMem(int procId, IntPtr addressToRead, int lengthToRead)
        {
            if (this.proc == IntPtr.Zero)
                this.proc = Win32.OpenProcess(Win32.ProcessAccessRights.PROCESS_ALL_ACCESS, false, procId);

            return ReadProcMem(addressToRead, lengthToRead);
        }

        public byte[] ReadProcMem(IntPtr addressToRead, int lengthToRead)
        {
            if (!Win32.VirtualProtectEx(this.proc, addressToRead, (UIntPtr)lengthToRead, Win32.MemoryProtectionConstants.PAGE_READONLY, out Win32.MemoryProtectionConstants oldProtect))
                throw new Exception(string.Format("ERROR: {0}", Marshal.GetLastWin32Error().ToString()));

            var buffer = new byte[lengthToRead];

            if (!Win32.ReadProcessMemory(this.proc, addressToRead, buffer, lengthToRead, out IntPtr bufferRead))
                throw new Exception(string.Format("ERROR: {0}",  Marshal.GetLastWin32Error().ToString()));

            return buffer;
        }

        public int WriteProcMem(IntPtr procHandle, IntPtr addressToWrite, byte[] bytesToWrite)
        {
            if (this.proc == IntPtr.Zero)
                this.proc = Win32.OpenProcess(Win32.ProcessAccessRights.PROCESS_ALL_ACCESS, false, procHandle.ToInt32());

            return WriteProcMem(addressToWrite, bytesToWrite);
        }

        public int WriteProcMem(IntPtr addressToWrite, byte[] bytesToWrite)
        {
            var newProtect = Win32.MemoryProtectionConstants.PAGE_READWRITE;
            if (!Win32.VirtualProtectEx(this.proc, addressToWrite, (UIntPtr)bytesToWrite.Length, newProtect, out Win32.MemoryProtectionConstants oldProtect))
                return 0;

            if (!Win32.WriteProcessMemory(this.proc, addressToWrite, bytesToWrite, bytesToWrite.Length, out int bufferWritten))
                return 0;

            if (!Win32.VirtualProtectEx(this.proc, addressToWrite, (UIntPtr)bytesToWrite.Length, oldProtect, out newProtect))
                return 0;

            return bufferWritten;
        }
    }
}
