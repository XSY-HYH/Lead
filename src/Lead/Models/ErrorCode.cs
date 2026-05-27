namespace Lead;

public static class ErrorCode
{
    public const string ScanFailed = "SCAN_FAILED";
    public const string ForbiddenType = "FORBIDDEN_TYPE";
    public const string ForbiddenMethod = "FORBIDDEN_METHOD";
    public const string ForbiddenAttribute = "FORBIDDEN_ATTRIBUTE";
    public const string UnsafeCode = "UNSAFE_CODE";
    public const string PInvoke = "PINVOKE";
    public const string PointerType = "POINTER_TYPE";
    public const string ForbiddenAssembly = "FORBIDDEN_ASSEMBLY";
    public const string PluginTypeNotFound = "PLUGIN_TYPE_NOT_FOUND";
    public const string PluginLoadFailed = "PLUGIN_LOAD_FAILED";
    public const string PluginNotFound = "PLUGIN_NOT_FOUND";
    public const string PluginCancelled = "PLUGIN_CANCELLED";

    public const string EmptyPath = "EMPTY_PATH";
    public const string PathTraversal = "PATH_TRAVERSAL";
    public const string PathEscape = "PATH_ESCAPE";
    public const string ForbiddenFileExt = "FORBIDDEN_FILE_EXT";
    public const string ReadOnlyMode = "READ_ONLY_MODE";
    public const string FileTooLarge = "FILE_TOO_LARGE";

    public const string InvalidUrl = "INVALID_URL";
    public const string ForbiddenProtocol = "FORBIDDEN_PROTOCOL";
    public const string ForbiddenUrl = "FORBIDDEN_URL";
    public const string PrivateIp = "PRIVATE_IP";
    public const string HttpFailed = "HTTP_FAILED";

    public const string ExecutionTimeout = "EXECUTION_TIMEOUT";
    public const string ReadLimitExceeded = "READ_LIMIT_EXCEEDED";
    public const string WriteLimitExceeded = "WRITE_LIMIT_EXCEEDED";
    public const string HttpLimitExceeded = "HTTP_LIMIT_EXCEEDED";

    public const string ServiceNotFound = "SERVICE_NOT_FOUND";
    public const string UnsafeParamType = "UNSAFE_PARAM_TYPE";
    public const string InvalidProgress = "INVALID_PROGRESS";
    public const string TimeRequestTooLong = "TIME_REQUEST_TOO_LONG";
    public const string OperationCancelled = "OPERATION_CANCELLED";
}
