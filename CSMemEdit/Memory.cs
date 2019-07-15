using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CSMemEdit
{
    class Memory
    {
        private IntPtr Proc { get; set; }

        public Memory() { }

        public Memory(int procId)
        {
            Proc = Win32.OpenProcess(Win32.ProcessAccessRights.PROCESS_ALL_ACCESS, false, procId);
            if (Proc == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == 5)
                    throw new Exception(string.Format("ERROR: OpenProcess error {0} try running as admin.", error));
                else
                    throw new Exception(string.Format("ERROR: OpenProcess error {0}", error));
            }
        }

        ~Memory()
        {
            Win32.CloseHandle(this.Proc);
        }

        public IntPtr GetProcessHandle()
        {
            return Proc;
        }

        public IntPtr GetProcessModuleHandle(string moduleName)
        {
            var hMods = new IntPtr[1024];

            var gch = GCHandle.Alloc(hMods, GCHandleType.Pinned);
            var pModules = gch.AddrOfPinnedObject();

            var uiSize = (uint)(Marshal.SizeOf(typeof(IntPtr)) * (hMods.Length));

            if (Win32.EnumProcessModules(Proc, pModules, uiSize, out uint cbNeeded) == 1)
            {
                var uiTotalNumberofModules = (Int32)(cbNeeded / (Marshal.SizeOf(typeof(IntPtr))));

                for (var i = 0; i < (int)uiTotalNumberofModules; ++i)
                {
                    var stringBuilder = new StringBuilder(1024);

                    Win32.GetModuleFileNameEx(Proc, hMods[i], stringBuilder, (uint)(stringBuilder.Capacity));
                    if (Path.GetFileName(stringBuilder.ToString().ToLower()) == moduleName.ToLower())
                        return hMods[i];
                }
            }

            gch.Free();

            return IntPtr.Zero;
        }

        public byte[] ReadProcMem(int procId, IntPtr addressToRead, int lengthToRead)
        {
            if (Proc == IntPtr.Zero)
                Proc = Win32.OpenProcess(Win32.ProcessAccessRights.PROCESS_ALL_ACCESS, false, procId);

            return ReadProcMem(addressToRead, lengthToRead);
        }

        public byte[] ReadProcMem(IntPtr addressToRead, int lengthToRead)
        {
            var newProtect = Win32.MemoryProtectionConstants.PAGE_READWRITE;
            if (!Win32.VirtualProtectEx(Proc, addressToRead, (UIntPtr)lengthToRead, newProtect, out Win32.MemoryProtectionConstants oldProtect))
                throw new Exception(string.Format("ERROR: ReadProcMem set VirtualProtectEx error {0}", Marshal.GetLastWin32Error().ToString()));

            var buffer = new byte[lengthToRead];

            if (!Win32.ReadProcessMemory(Proc, addressToRead, buffer, lengthToRead, out IntPtr bufferRead))
                throw new Exception(string.Format("ERROR: ReadProcMem ReadProcessMemory error {0}", Marshal.GetLastWin32Error().ToString()));

            if (!Win32.VirtualProtectEx(Proc, addressToRead, (UIntPtr)lengthToRead, oldProtect, out newProtect))
                throw new Exception(string.Format("ERROR: ReadProcMem unset VirtualProtectEx error {0}", Marshal.GetLastWin32Error().ToString()));

            Win32.FlushInstructionCache(Proc, addressToRead, (UIntPtr)lengthToRead);

            return buffer;
        }

        public int WriteProcMem(IntPtr procHandle, IntPtr addressToWrite, byte[] bytesToWrite)
        {
            if (Proc == IntPtr.Zero)
                Proc = Win32.OpenProcess(Win32.ProcessAccessRights.PROCESS_ALL_ACCESS, false, procHandle.ToInt32());

            return WriteProcMem(addressToWrite, bytesToWrite);
        }

        public int WriteProcMem(IntPtr addressToWrite, byte[] bytesToWrite)
        {
            var newProtect = Win32.MemoryProtectionConstants.PAGE_READWRITE;
            if (!Win32.VirtualProtectEx(Proc, addressToWrite, (UIntPtr)bytesToWrite.Length, newProtect, out Win32.MemoryProtectionConstants oldProtect))
                throw new Exception(string.Format("ERROR: WriteProcMem set VirtualProtectEx error {0}", Marshal.GetLastWin32Error().ToString()));

            if (!Win32.WriteProcessMemory(Proc, addressToWrite, bytesToWrite, bytesToWrite.Length, out int bufferWritten))
                throw new Exception(string.Format("ERROR: WriteProcMem WriteProcessMemory error {0}", Marshal.GetLastWin32Error().ToString()));

            if (!Win32.VirtualProtectEx(Proc, addressToWrite, (UIntPtr)bytesToWrite.Length, oldProtect, out newProtect))
                throw new Exception(string.Format("ERROR: WriteProcMem unset VirtualProtectEx error {0}", Marshal.GetLastWin32Error().ToString()));

            Win32.FlushInstructionCache(Proc, addressToWrite, (UIntPtr)bytesToWrite.Length);

            return bufferWritten;
        }

        public IntPtr QuickSearch(uint lowerAddress, uint upperAddress, short[] searchPattern)
        {
            uint addr = 0;

            for (var i = lowerAddress; i < upperAddress; ++i)
            {
                var found = true;
                for (var x = 0; x < searchPattern.Length; ++x)
                {
                    var read = ReadProcMem((IntPtr)i + x, 1);
                    if ((searchPattern[x] & 0xFF00) > 0)
                        continue;

                    if (read[0] != (searchPattern[x] & 0x00FF))
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    addr = i;
                    break;
                }
            }

            return (IntPtr)addr;
        }
    }
}
