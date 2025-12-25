using System.Runtime.InteropServices;
using Lunar.Native;
using Lunar.Shellcode.Records;

namespace Lunar.Shellcode;

internal static class Assembler
{
    // MODIFICACION POR MOONLIGHT
    private static void Junker(List<byte> shellcode)
    {
        // Lista de instrucciones NOP
        var junkInstructions = new List<byte[]>
    {
        new byte[] { 0x90 },                            // NOP (1 byte)
        new byte[] { 0x66, 0x90 },                      // 66 NOP (2 bytes)
        new byte[] { 0x0F, 0x1F, 0x00 },                // NOP (3 bytes)
        new byte[] { 0x0F, 0x1F, 0x40, 0x00 },          // NOP (4 bytes) - [rax+00]
        new byte[] { 0x0F, 0x1F, 0x44, 0x00, 0x00 },    // NOP (5 bytes) - [rax+rax+00]
        new byte[] { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 }, // NOP (6 bytes)
    };
        int numberOfJunkInstructions = Random.Shared.Next(1, 3);

        for (int i = 0; i < numberOfJunkInstructions; i++)
        {
            var junk = junkInstructions[Random.Shared.Next(junkInstructions.Count)];
            shellcode.AddRange(junk);
        }
    }

    internal static Span<byte> AssembleCall32(CallDescriptor<int> descriptor)
    {
        var shellcode = new List<byte>();
        if (descriptor.CallingConvention == CallingConvention.FastCall)
        {
            if (descriptor.Arguments.Count > 0)
            {
                var argument = descriptor.Arguments[0];
                if (argument == 0)
                {
                    // xor ecx, ecx
                    shellcode.AddRange(new byte[] { 0x31, 0xC9 });
                }
                else
                {
                    // mov ecx, argument
                    shellcode.Add(0xB9);
                    shellcode.AddRange(BitConverter.GetBytes(argument));
                }
            }

            if (descriptor.Arguments.Count > 1)
            {
                var argument = descriptor.Arguments[1];

                if (argument == 0)
                {
                    // xor edx, edx
                    shellcode.AddRange(new byte[] { 0x31, 0xD2 });
                }
                else
                {
                    // mov edx, argument
                    shellcode.Add(0xBA);
                    shellcode.AddRange(BitConverter.GetBytes(argument));
                }
            }
        }
        foreach (var argument in descriptor.Arguments.Skip(descriptor.CallingConvention == CallingConvention.FastCall ? 2 : 0).Reverse())
        {
            switch (argument)
            {
                case >= sbyte.MinValue and <= sbyte.MaxValue:
                {
                    // push argument
                    shellcode.AddRange(new byte[] { 0x6A, unchecked((byte)argument) });
                    break;
                }
                default:
                {
                    // push argument
                    shellcode.Add(0x68);
                    shellcode.AddRange(BitConverter.GetBytes(argument));
                    break;
                }
            }
        }
        // mov eax, Address
        shellcode.Add(0xB8);
        shellcode.AddRange(BitConverter.GetBytes((int)descriptor.Address));

        // call eax
        shellcode.AddRange(new byte[] { 0xFF, 0xD0 });

        if (descriptor.ReturnAddress is not null)
        {
            // mov [ReturnAddress], eax
            shellcode.Add(0xA3);
            shellcode.AddRange(BitConverter.GetBytes((int)descriptor.ReturnAddress.Value));
        }

        // xor eax, eax
        shellcode.AddRange(new byte[] { 0x31, 0xC0 });

        // ret
        shellcode.Add(0xC3);
        return CollectionsMarshal.AsSpan(shellcode);
    }

    // MODIFICACION POR MOONLIGHT
    // En lugar de usar siempre RAX, usaremos aleatoriamente R10 o R11 para evitar detección por firmas simple
    internal static Span<byte> AssembleCall64(CallDescriptor<long> descriptor)
    {
        var shellcode = new List<byte>();

        // Espacio en stack
        var shadowSpaceSize = Constants.ShadowSpaceSize + sizeof(long) * Math.Max(0, descriptor.Arguments.Count - 4);

        // sub rsp, shadowSpaceSize
        shellcode.AddRange(new byte[] { 0x48, 0x83, 0xEC, (byte)shadowSpaceSize });

        // [MOONLIGHT] 1
        Junker(shellcode);
        if (descriptor.Arguments.Count > 0)
        {
            var argument = descriptor.Arguments[0];
            switch (argument)
            {
                case 0:
                    shellcode.AddRange(new byte[] { 0x31, 0xC9 }); // xor ecx, ecx
                    break;
                case >= int.MinValue and <= uint.MaxValue:
                    shellcode.Add(0xB9);
                    shellcode.AddRange(BitConverter.GetBytes((int)argument));
                    break;
                default:
                    shellcode.AddRange(new byte[] { 0x48, 0xB9 });
                    shellcode.AddRange(BitConverter.GetBytes(argument));
                    break;
            }
            // [MOONLIGHT]
            Junker(shellcode);
        }
        if (descriptor.Arguments.Count > 1)
        {
            var argument = descriptor.Arguments[1];
            switch (argument)
            {
                case 0:
                    shellcode.AddRange(new byte[] { 0x31, 0xD2 }); // xor edx, edx
                    break;
                case >= int.MinValue and <= uint.MaxValue:
                    shellcode.Add(0xBA);
                    shellcode.AddRange(BitConverter.GetBytes((int)argument));
                    break;
                default:
                    shellcode.AddRange(new byte[] { 0x48, 0xBA });
                    shellcode.AddRange(BitConverter.GetBytes(argument));
                    break;
            }
        }

        if (descriptor.Arguments.Count > 2)
        {
            var argument = descriptor.Arguments[2];
            switch (argument)
            {
                case 0:
                    shellcode.AddRange(new byte[] { 0x4D, 0x31, 0xC0 }); // xor r8, r8
                    break;
                case >= int.MinValue and <= uint.MaxValue:
                    shellcode.AddRange(new byte[] { 0x41, 0xB8 });
                    shellcode.AddRange(BitConverter.GetBytes((int)argument));
                    break;
                default:
                    shellcode.AddRange(new byte[] { 0x49, 0xB8 });
                    shellcode.AddRange(BitConverter.GetBytes(argument));
                    break;
            }
        }

        if (descriptor.Arguments.Count > 3)
        {
            var argument = descriptor.Arguments[3];
            switch (argument)
            {
                case 0:
                    shellcode.AddRange(new byte[] { 0x4D, 0x31, 0xC9 }); // xor r9, r9
                    break;
                case >= int.MinValue and <= uint.MaxValue:
                    shellcode.AddRange(new byte[] { 0x41, 0xB9 });
                    shellcode.AddRange(BitConverter.GetBytes((int)argument));
                    break;
                default:
                    shellcode.AddRange(new byte[] { 0x49, 0xB9 });
                    shellcode.AddRange(BitConverter.GetBytes(argument));
                    break;
            }
            // [MOONLIGHT]
            Junker(shellcode);
        }

        if (descriptor.Arguments.Count > 4)
        {
            foreach (var argument in descriptor.Arguments.Skip(4).Reverse())
            {
                switch (argument)
                {
                    case >= sbyte.MinValue and <= sbyte.MaxValue:
                        shellcode.AddRange(new byte[] { 0x6A, unchecked((byte)argument) });
                        break;
                    case >= int.MinValue and <= int.MaxValue:
                        shellcode.Add(0x68);
                        shellcode.AddRange(BitConverter.GetBytes((int)argument));
                        break;
                    default:
                        shellcode.AddRange(new byte[] { 0x48, 0xB8 });
                        shellcode.AddRange(BitConverter.GetBytes(argument));
                        shellcode.Add(0x50);
                        break;
                }
            }
        }

        // [MOONLIGHT] POLIMORFISMO EN LA LLAMADA
        // Se usa aleatoriamente R10 o RAX
        bool useR10 = Random.Shared.Next(0, 2) == 0;

        if (useR10)
        {
            // Usar R10
            // mov r10, Address
            shellcode.AddRange(new byte[] { 0x49, 0xBA });
            shellcode.AddRange(BitConverter.GetBytes(descriptor.Address));

            // Basura vital para separar el MOV del CALL
            Junker(shellcode);

            // call r10
            shellcode.AddRange(new byte[] { 0x41, 0xFF, 0xD2 });
        }
        else
        {
            // Usar RAX (Original)
            // mov rax, Address
            shellcode.AddRange(new byte[] { 0x48, 0xB8 });
            shellcode.AddRange(BitConverter.GetBytes(descriptor.Address));

            // Basura vital
            Junker(shellcode);

            // call rax
            shellcode.AddRange(new byte[] { 0xFF, 0xD0 });
        }

        // Retorno y limpieza
        if (descriptor.ReturnAddress is not null)
        {
            // mov [ReturnAddress], rax
            shellcode.AddRange(new byte[] { 0x48, 0xA3 });
            shellcode.AddRange(BitConverter.GetBytes(descriptor.ReturnAddress.Value));
        }

        // xor eax, eax
        shellcode.AddRange(new byte[] { 0x31, 0xC0 });

        // add rsp, shadowSpaceSize
        shellcode.AddRange(new byte[] { 0x48, 0x83, 0xC4, (byte)shadowSpaceSize });

        // ret
        shellcode.Add(0xC3);

        return CollectionsMarshal.AsSpan(shellcode);
    }
}