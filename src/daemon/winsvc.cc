extern "C" {

#include "daemon.h"
#include "libnetdata/libnetdata.h"
#include "daemon/daemon-shutdown.h"

int netdata_main(int argc, char *argv[]);
void nd_process_signals(void);

}

__attribute__((format(printf, 2, 3)))
static void netdata_service_log_impl(WORD wType, const char *fmt, ...)
{
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintfz(buf, sizeof(buf) - 1, fmt, args);
    va_end(args);

    // Write to log file
    char path[FILENAME_MAX + 1];
    snprintfz(path, FILENAME_MAX, "%s/service.log", LOG_DIR);
    FILE *fp = fopen(path, "a");
    if (fp != NULL) {
        SYSTEMTIME st;
        GetSystemTime(&st);
        fprintf(fp, "%02d:%02d:%02d - %s\n", st.wHour, st.wMinute, st.wSecond, buf);
        fflush(fp);
        fclose(fp);
    }

    // Write to Windows Event Log so events appear in Event Viewer during Sophos debugging
    HANDLE hEventSource = RegisterEventSourceA(NULL, "NetdataDaemon");
    if (hEventSource) {
        LPCSTR strings[1] = { buf };
        ReportEventA(hEventSource, wType, 0, 0, NULL, 1, 0, strings, NULL);
        DeregisterEventSource(hEventSource);
    }
}

#define netdata_service_log(fmt, ...)       netdata_service_log_impl(EVENTLOG_INFORMATION_TYPE, fmt, ##__VA_ARGS__)
#define netdata_service_log_error(fmt, ...) netdata_service_log_impl(EVENTLOG_ERROR_TYPE,       fmt, ##__VA_ARGS__)

static SERVICE_STATUS_HANDLE svc_status_handle = nullptr;
static SERVICE_STATUS svc_status = {};

static HANDLE svc_stop_event_handle = nullptr;

static ND_THREAD *cleanup_thread = nullptr;

static bool ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint, DWORD dwControlsAccepted)
{
    static DWORD dwCheckPoint = 1;
    svc_status.dwCurrentState = dwCurrentState;
    svc_status.dwWin32ExitCode = dwWin32ExitCode;
    svc_status.dwWaitHint = dwWaitHint;
    svc_status.dwControlsAccepted = dwControlsAccepted;

    if (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED)
    {
        svc_status.dwCheckPoint = 0;
    }
    else
    {
        svc_status.dwCheckPoint = dwCheckPoint++;
    }

    if (!SetServiceStatus(svc_status_handle, &svc_status)) {
        netdata_service_log_error("@ReportSvcStatus: SetServiceStatusFailed (%d)", GetLastError());
        return false;
    }

    return true;
}

static HANDLE CreateEventHandle(const char *msg)
{
    HANDLE h = CreateEvent(NULL, TRUE, FALSE, NULL);

    if (!h)
    {
        netdata_service_log_error("%s", msg);

        if (!ReportSvcStatus(SERVICE_STOPPED, GetLastError(), 1000, 0))
        {
            netdata_service_log_error("Failed to set service status to stopped.");
        }

        return NULL;
    }

    return h;
}

static void call_netdata_cleanup(void *arg)
{
    DWORD controlCode = *((DWORD *)arg);

    // Wait until we have to stop the service
    netdata_service_log("Cleanup thread waiting for stop event...");
    WaitForSingleObject(svc_stop_event_handle, INFINITE);

    // Stop the agent
    netdata_service_log("Running netdata cleanup...");
    EXIT_REASON reason;
    switch(controlCode) {
        case SERVICE_CONTROL_SHUTDOWN:
            reason = (EXIT_REASON)(EXIT_REASON_SERVICE_STOP|EXIT_REASON_SYSTEM_SHUTDOWN);
            break;

        case SERVICE_CONTROL_STOP:
            // fall-through

        default:
            reason = EXIT_REASON_SERVICE_STOP;
            break;
    }
    netdata_exit_gracefully(reason, false);

    // Close event handle
    netdata_service_log("Closing stop event handle...");
    CloseHandle(svc_stop_event_handle);

    // Set status to stopped
    netdata_service_log("Reporting the service as stopped...");
    ReportSvcStatus(SERVICE_STOPPED, 0, 0, 0);
}

static void WINAPI ServiceControlHandler(DWORD controlCode)
{
    switch (controlCode)
    {
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_STOP:
        {
            if (svc_status.dwCurrentState != SERVICE_RUNNING)
                return;

            // Set service status to stop-pending
            netdata_service_log("Setting service status to stop-pending...");
            if (!ReportSvcStatus(SERVICE_STOP_PENDING, 0, 5000, 0))
                return;

            // Create cleanup thread
            netdata_service_log("Creating cleanup thread...");
            char tag[NETDATA_THREAD_TAG_MAX + 1];
            snprintfz(tag, NETDATA_THREAD_TAG_MAX, "%s", "CLEANUP");
            cleanup_thread = nd_thread_create(tag, NETDATA_THREAD_OPTION_DEFAULT, call_netdata_cleanup, &controlCode);

            // Signal the stop request
            netdata_service_log("Signalling the cleanup thread...");
            SetEvent(svc_stop_event_handle);
            break;
        }
        case SERVICE_CONTROL_INTERROGATE:
        {
            ReportSvcStatus(svc_status.dwCurrentState, svc_status.dwWin32ExitCode, svc_status.dwWaitHint, svc_status.dwControlsAccepted);
            break;
        }
        default:
            break;
    }
}

void WINAPI ServiceMain(DWORD argc, LPSTR* argv)
{
    UNUSED(argc);
    UNUSED(argv);

    // Create service status handle
    netdata_service_log("Creating service status handle...");
    svc_status_handle = RegisterServiceCtrlHandler("Netdata", ServiceControlHandler);
    if (!svc_status_handle)
    {
        netdata_service_log_error("@ServiceMain() - RegisterServiceCtrlHandler() failed...");
        return;
    }

    // Set status to start-pending
    netdata_service_log("Setting service status to start-pending...");
    svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    svc_status.dwServiceSpecificExitCode = 0;
    svc_status.dwCheckPoint = 0;
    if (!ReportSvcStatus(SERVICE_START_PENDING, 0, 5000, 0))
    {
        netdata_service_log_error("Failed to set service status to start pending.");
        return;
    }

    // Create stop service event handle
    netdata_service_log("Creating stop service event handle...");
    svc_stop_event_handle = CreateEventHandle("Failed to create stop event handle");
    if (!svc_stop_event_handle)
        return;

    // Set status to running
    netdata_service_log("Setting service status to running...");
    if (!ReportSvcStatus(SERVICE_RUNNING, 0, 5000, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN))
    {
        netdata_service_log_error("Failed to set service status to running.");
        return;
    }

    // Run the agent
    netdata_service_log("Running the agent...");
    netdata_main(argc, argv);

    netdata_service_log("Agent has been started...");
}

static bool update_path() {
    const char *old_path = getenv("PATH");

    if (!old_path) {
        if (setenv("PATH", "/usr/bin", 1) != 0) {
            netdata_service_log_error("Failed to set PATH to /usr/bin");
            return false;
        }

        return true;
    }

    size_t new_path_length = strlen(old_path) + strlen("/usr/bin") + 2;
    char *new_path = (char *) callocz(new_path_length, sizeof(char));
    snprintfz(new_path, new_path_length, "/usr/bin:%s", old_path);

    if (setenv("PATH", new_path, 1) != 0) {
        netdata_service_log_error("Failed to add /usr/bin to PATH");
        freez(new_path);
        return false;
    }

    freez(new_path);
    return true;
}

int main(int argc, char *argv[])
{
#if defined(OS_WINDOWS) && defined(RUN_UNDER_CLION)
    bool tty = true;
#else
    bool tty = isatty(fileno(stdin)) == 1;
#endif

    if (!update_path()) {
        return 1;
    }

    if (tty)
    {
        int rc = netdata_main(argc, argv);
        if (rc != 10)
            return rc;

        nd_process_signals();
        return 1;
    }
    else
    {
        SERVICE_TABLE_ENTRY serviceTable[] = {
            { strdupz("Netdata"), ServiceMain },
            { nullptr, nullptr }
        };

        if (!StartServiceCtrlDispatcher(serviceTable))
        {
            netdata_service_log_error("@main() - StartServiceCtrlDispatcher() failed...");
            return 1;
        }

        return 0;
    }
}
