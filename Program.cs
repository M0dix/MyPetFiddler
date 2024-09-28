using Fiddler;
using System.Reflection;
using System.Text;

internal static class Program
{
    private const ushort defaultListenPort = 12345;

    private static readonly ICollection<Session> sessions = new HashSet<Session>();
    private static readonly ReaderWriterLockSlim sessionsLock = new ReaderWriterLockSlim();

    private static readonly string assemblyDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);

    public static void Main(string[] args)
    {
        EnsureRootCertificate();

        AttachEventListeners();

        StartupFiddlerCore(GetListenPortFromUser());

        ExecuteUserCommands();

        Quit();
    }

    private static void EnsureRootCertificate()
    {
        BCCertMaker.BCCertMaker certProvider = new BCCertMaker.BCCertMaker();
        CertMaker.oCertProvider = certProvider;

        string rootCertificatePath = Path.Combine(assemblyDirectory, "..", "..", "RootCertificate.p12");
        string rootCertificatePassword = "2DSAJKL2sdjkasJSDwj";

        if (!File.Exists(rootCertificatePath))
        {
            certProvider.CreateRootCertificate();
            certProvider.WriteRootCertificateAndPrivateKeyToPkcs12File(rootCertificatePath, rootCertificatePassword);
        }
        else
        {
            certProvider.ReadRootCertificateAndPrivateKeyFromPkcs12File(rootCertificatePath, rootCertificatePassword);
        }

        if (!CertMaker.rootCertIsTrusted())
        {
            CertMaker.trustRootCert();
        }
    }

    private static void AttachEventListeners()
    {
        // Before request section
        FiddlerApplication.BeforeRequest += session =>
        {
            try
            {
                sessionsLock.EnterWriteLock();
                sessions.Add(session);
            }
            finally
            {
                sessionsLock.ExitWriteLock();
            }
        };

        Console.CancelKeyPress += (o, ccea) =>
        {
            Quit();
        };
    }

    private static ushort GetListenPortFromUser()
    {
        Console.WriteLine($"Введите порт для прослушивания или просто нажмите Enter чтобы выбрать порт по умолчанию {defaultListenPort}");
        Console.Write(">");

        while (true)
        {
            string? input = Console.ReadLine();

            if (string.IsNullOrEmpty(input))
            {
                Console.WriteLine($"Получено пустое значение, выбран порт по умолчанию: {defaultListenPort}");
                return defaultListenPort;
            }
            else
            {
                if (ushort.TryParse(input, out ushort port))
                {
                    if (port >= 1 && port <= 65535)
                    {
                        Console.WriteLine($"Выбран порт: {port}");
                        return port;
                    }
                    else
                    {
                        Console.WriteLine("Порт должен быть в диапазоне от 1 до 65535. Попробуйте снова.");
                    }
                }
                else
                {
                    Console.WriteLine("Некорректный ввод. Пожалуйста, попробуйте снова.");
                }
            }
        }
    }

    private static void StartupFiddlerCore(ushort port)
    {
        FiddlerCoreStartupSettings fiddlerCoreStartupSettings =
            new FiddlerCoreStartupSettingsBuilder()
                .ListenOnPort(port)
                .RegisterAsSystemProxy()
                .ChainToUpstreamGateway()
                .DecryptSSL()
                .OptimizeThreadPool()
                .Build();

        FiddlerApplication.Startup(fiddlerCoreStartupSettings);
    }

    private static void ExecuteUserCommands()
    {
        bool done = false;

        do
        {
            Console.WriteLine("Введите команду [C=очистить;L=Вывести список сессий;R=Задать редирект;P=Изменить порт;Q=Выйти]:");
            Console.Write(">");
            ConsoleKeyInfo cki = Console.ReadKey();
            Console.WriteLine();

            switch (char.ToLower(cki.KeyChar))
            {
                case 'c':
                    ClearSessions();
                    break;

                case 'l':
                    WriteSessions(sessions);
                    break;

                case 'r':
                    CreateRedirect();
                    break;

                case 'p':
                    ChangePort();
                    break;

                case 'q':
                    done = true;
                    break;

                default:
                    Console.WriteLine("Неверный ввод");
                    break;
            }
        } while (!done);
    }

    private static void Quit()
    {
        Console.WriteLine("Выход..");
        FiddlerApplication.Shutdown();
    }

    private static void WriteSessions(IEnumerable<Session> sessions)
    {
        ConsoleColor oldColor = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.White;
        StringBuilder sb = new StringBuilder($"Список сессий: {Environment.NewLine}");

        try
        {
            sessionsLock.EnterReadLock();
            foreach (Session s in sessions)
            {
                sb.AppendLine($"{s.id} {s.oRequest.headers.HTTPMethod} {Ellipsize(s.fullUrl, 60)}");
                sb.AppendLine($"{s.responseCode} {s.oResponse.MIMEType}{Environment.NewLine}");
            }
        }
        finally
        {
            sessionsLock.ExitReadLock();
        }

        Console.Write(sb.ToString());
        Console.ForegroundColor = oldColor;
    }
    private static string Ellipsize(string text, int length)
    {
        if (Equals(text, null)) throw new ArgumentNullException(nameof(text));

        const int minLength = 3;

        if (length < minLength) throw new ArgumentOutOfRangeException(nameof(length), $"{nameof(length)} cannot be less than {minLength}");

        if (text.Length <= length) return text;

        return text.Substring(0, length - minLength) + new string('.', minLength);
    }

    private static void CreateRedirect()
    {
        Console.WriteLine("Введите часть URL, с которого хотите делать редирект");
        string? targetHost = Console.ReadLine();
        Console.WriteLine($"Часть URL, с которого будет выполнен редирект:{targetHost}");

        Console.WriteLine("Введите адрес, куда выполнить редирект:");
        string? redirectUrl = Console.ReadLine();
        Console.WriteLine($"URL, на который будет выполнен редирект: {redirectUrl}");

        AttachRedirectRule(targetHost, redirectUrl);
    }

    private static void ChangePort()
    {
        FiddlerApplication.oProxy.Detach();

        FiddlerApplication.Shutdown();

        ClearSessions();

        StartupFiddlerCore(GetListenPortFromUser());
    }

    private static void ClearSessions()
    {
        try
        {
            sessionsLock.EnterWriteLock();
            sessions.Clear();
        }
        finally
        {
            sessionsLock.ExitWriteLock();
        }
    }

    private static void AttachRedirectRule(string? targetHost, string? redirectUrl)
    {
        FiddlerApplication.BeforeRequest += session =>
        {
            if (session.uriContains(targetHost) && session.RequestMethod == "GET")
            {
                session.utilCreateResponseAndBypassServer();
                session.oResponse.headers.SetStatus(302, "Found");
                session.oResponse["Cache-Control"] = "nocache";
                session.oResponse["Location"] = redirectUrl;
                session.utilSetResponseBody($"<html><body>Redirecting to {redirectUrl}...</body></html>");
            }
        };
    }
}