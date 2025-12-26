using System;
using System.Diagnostics;
using System.IO;
using Lunar;

namespace TestLoader
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("--- Cargador Lunar (Prueba) ---");

            // 1. CONFIGURACIÓN
            // Cambia esto por la ruta de una DLL de prueba (ej. una DLL simple de C++ que muestre un mensaje)
            string rutaDllCheat = @"..\src\Lunar\bin\Debug\net8.0\Moonlight.dll";
            string nombreProceso = "javaw"; // El proceso de Minecraft

            // Verificamos que el archivo exista
            if (!File.Exists(rutaDllCheat))
            {
                Console.WriteLine($"[Error] No encuentro la DLL en: {rutaDllCheat}");
                Console.ReadKey();
                return;
            }

            Console.WriteLine($"Buscando proceso: {nombreProceso}...");

            try
            {
                // 2. BUSCAR EL PROCESO
                var procesos = Process.GetProcessesByName(nombreProceso);
                if (procesos.Length == 0)
                {
                    Console.WriteLine("[Error] Minecraft no está abierto.");
                    Console.ReadKey();
                    return;
                }
                var procesoMinecraft = procesos[0];
                Console.WriteLine($"[Info] Proceso encontrado ID: {procesoMinecraft.Id}");

                // 3. PREPARAR LOS BYTES
                // Leemos tu DLL de cheat y la convertimos en bytes (como si viniera del servidor)
                byte[] dllBytes = File.ReadAllBytes(rutaDllCheat);

                // 4. INYECTAR USANDO LUNAR
                Console.WriteLine("[Info] Iniciando inyección con Lunar...");

                // Usamos el flag DiscardHeaders para el modo "Ghost" (borra la cabecera PE)
                var flags = MappingFlags.DiscardHeaders;

                var mapper = new LibraryMapper(procesoMinecraft, dllBytes, flags);
                mapper.MapLibrary();

                Console.WriteLine("[Exito] ¡DLL Inyectada invisiblemente!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Fatal] Error al inyectar: {ex.Message}");
            }

            Console.ReadKey();
        }
    }
}
