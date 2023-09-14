-- https://luajit.org/ext_ffi_api.html
-- https://www.libssh2.org/examples/ssh2.html
-- https://gist.github.com/CapsAdmin/bc45cc45c11cbfd1eff8c43c8eb5071b

local socket = require("socket")
local ffi = require("ffi")

LIBSSH2_COPYRIGHT = "2004-2016 The libssh2 project and its contributors."
LIBSSH2_VERSION = "1.8.0"
LIBSSH2_VERSION_MAJOR = 1
LIBSSH2_VERSION_MINOR = 8
LIBSSH2_VERSION_PATCH = 0

LIBSSH2_VERSION_NUM = 0x010800

LIBSSH2_TIMESTAMP = "Tue Oct 25 06:44:33 UTC 2016"

LIBSSH2_SSH_BANNER = "SSH-2.0-libssh2_" .. LIBSSH2_VERSION

LIBSSH2_SSH_DEFAULT_BANNER = LIBSSH2_SSH_BANNER
LIBSSH2_SSH_DEFAULT_BANNER_WITH_CRLF = LIBSSH2_SSH_DEFAULT_BANNER .. "\r\n"

LIBSSH2_DH_GEX_MINGROUP = 1024
LIBSSH2_DH_GEX_OPTGROUP = 1536
LIBSSH2_DH_GEX_MAXGROUP = 2048

-- Defaults for pty requests.
LIBSSH2_TERM_WIDTH = 80
LIBSSH2_TERM_HEIGHT = 24
LIBSSH2_TERM_WIDTH_PX = 0
LIBSSH2_TERM_HEIGHT_PX = 0

-- 1/4 second.
LIBSSH2_SOCKET_POLL_UDELAY = 250000
-- 0.25 * 120 == 30 seconds.
LIBSSH2_SOCKET_POLL_MAXLOOPS = 120

-- Maximum size to allow a payload to compress to, plays it safe by falling
-- short of spec limits.
LIBSSH2_PACKET_MAXCOMP = 32000

-- Maximum size to allow a payload to deccompress to, plays it safe by allowing
-- more than spec requires.
LIBSSH2_PACKET_MAXDECOMP = 40000

-- Maximum size for an inbound compressed payload, plays it safe by
-- overshooting spec limits.
LIBSSH2_PACKET_MAXPAYLOAD = 40000

-- libssh2_session_callback_set() constants.
LIBSSH2_CALLBACK_IGNORE = 0
LIBSSH2_CALLBACK_DEBUG = 1
LIBSSH2_CALLBACK_DISCONNECT = 2
LIBSSH2_CALLBACK_MACERROR = 3
LIBSSH2_CALLBACK_X11 = 4
LIBSSH2_CALLBACK_SEND = 5
LIBSSH2_CALLBACK_RECV = 6

-- libssh2_session_method_pref() constants.
LIBSSH2_METHOD_KEX = 0
LIBSSH2_METHOD_HOSTKEY = 1
LIBSSH2_METHOD_CRYPT_CS = 2
LIBSSH2_METHOD_CRYPT_SC = 3
LIBSSH2_METHOD_MAC_CS = 4
LIBSSH2_METHOD_MAC_SC = 5
LIBSSH2_METHOD_COMP_CS = 6
LIBSSH2_METHOD_COMP_SC = 7
LIBSSH2_METHOD_LANG_CS = 8
LIBSSH2_METHOD_LANG_SC = 9

-- Flags.
LIBSSH2_FLAG_SIGPIPE = 1
LIBSSH2_FLAG_COMPRESS = 2

-- Poll FD Descriptor Types.
LIBSSH2_POLLFD_SOCKET = 1
LIBSSH2_POLLFD_CHANNEL = 2
LIBSSH2_POLLFD_LISTENER = 3

-- Poll FD events/revents -- Match sys/poll.h where possible.
LIBSSH2_POLLFD_POLLIN = 0x0001
LIBSSH2_POLLFD_POLLPRI = 0x0002
LIBSSH2_POLLFD_POLLEXT = 0x0002
LIBSSH2_POLLFD_POLLOUT = 0x0004
LIBSSH2_POLLFD_POLLERR = 0x0008
LIBSSH2_POLLFD_POLLHUP = 0x0010
LIBSSH2_POLLFD_SESSION_CLOSED = 0x0010
LIBSSH2_POLLFD_POLLNVAL = 0x0020
LIBSSH2_POLLFD_POLLEX = 0x0040
LIBSSH2_POLLFD_CHANNEL_CLOSED = 0x0080
LIBSSH2_POLLFD_LISTENER_CLOSED = 0x0080

-- HAVE_LIBSSH2_SESSION_BLOCK_DIRECTION
-- Block Direction Types.
LIBSSH2_SESSION_BLOCK_INBOUND = 0x0001
LIBSSH2_SESSION_BLOCK_OUTBOUND = 0x0002

-- Hash Types.
LIBSSH2_HOSTKEY_HASH_MD5 = 1
LIBSSH2_HOSTKEY_HASH_SHA1 = 2

-- Hostkey Types.
LIBSSH2_HOSTKEY_TYPE_UNKNOWN = 0
LIBSSH2_HOSTKEY_TYPE_RSA = 1
LIBSSH2_HOSTKEY_TYPE_DSS = 2

-- Disconnect Codes (defined by SSH protocol).
SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1
SSH_DISCONNECT_PROTOCOL_ERROR = 2
SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3
SSH_DISCONNECT_RESERVED = 4
SSH_DISCONNECT_MAC_ERROR = 5
SSH_DISCONNECT_COMPRESSION_ERROR = 6
SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7
SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8
SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9
SSH_DISCONNECT_CONNECTION_LOST = 10
SSH_DISCONNECT_BY_APPLICATION = 11
SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12
SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13
SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14
SSH_DISCONNECT_ILLEGAL_USER_NAME = 15

-- Error Codes (defined by libssh2).
LIBSSH2_ERROR_NONE = 0

LIBSSH2_ERROR_SOCKET_NONE = -1

LIBSSH2_ERROR_BANNER_RECV = -2
LIBSSH2_ERROR_BANNER_SEND = -3
LIBSSH2_ERROR_INVALID_MAC = -4
LIBSSH2_ERROR_KEX_FAILURE = -5
LIBSSH2_ERROR_ALLOC = -6
LIBSSH2_ERROR_SOCKET_SEND = -7
LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE = -8
LIBSSH2_ERROR_TIMEOUT = -9
LIBSSH2_ERROR_HOSTKEY_INIT = -10
LIBSSH2_ERROR_HOSTKEY_SIGN = -11
LIBSSH2_ERROR_DECRYPT = -12
LIBSSH2_ERROR_SOCKET_DISCONNECT = -13
LIBSSH2_ERROR_PROTO = -14
LIBSSH2_ERROR_PASSWORD_EXPIRED = -15
LIBSSH2_ERROR_FILE = -16
LIBSSH2_ERROR_METHOD_NONE = -17
LIBSSH2_ERROR_AUTHENTICATION_FAILED = -18
LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED = LIBSSH2_ERROR_AUTHENTICATION_FAILED
LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED = -19
LIBSSH2_ERROR_CHANNEL_OUTOFORDER = -20
LIBSSH2_ERROR_CHANNEL_FAILURE = -21
LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED = -22
LIBSSH2_ERROR_CHANNEL_UNKNOWN = -23
LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED = -24
LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED = -25
LIBSSH2_ERROR_CHANNEL_CLOSED = -26
LIBSSH2_ERROR_CHANNEL_EOF_SENT = -27
LIBSSH2_ERROR_SCP_PROTOCOL = -28
LIBSSH2_ERROR_ZLIB = -29
LIBSSH2_ERROR_SOCKET_TIMEOUT = -30
LIBSSH2_ERROR_SFTP_PROTOCOL = -31
LIBSSH2_ERROR_REQUEST_DENIED = -32
LIBSSH2_ERROR_METHOD_NOT_SUPPORTED = -33
LIBSSH2_ERROR_INVAL = -34
LIBSSH2_ERROR_INVALID_POLL_TYPE = -35
LIBSSH2_ERROR_PUBLICKEY_PROTOCOL = -36
LIBSSH2_ERROR_EAGAIN = -37
LIBSSH2_ERROR_BUFFER_TOO_SMALL = -38
LIBSSH2_ERROR_BAD_USE = -39
LIBSSH2_ERROR_COMPRESS = -40
LIBSSH2_ERROR_OUT_OF_BOUNDARY = -41
LIBSSH2_ERROR_AGENT_PROTOCOL = -42
LIBSSH2_ERROR_SOCKET_RECV = -43
LIBSSH2_ERROR_ENCRYPT = -44
LIBSSH2_ERROR_BAD_SOCKET = -45
LIBSSH2_ERROR_KNOWN_HOSTS = -46

-- This is a define to provide the old (<= 1.2.7) name.
LIBSSH2_ERROR_BANNER_NONE = LIBSSH2_ERROR_BANNER_RECV

-- Global API.
LIBSSH2_INIT_NO_CRYPTO = 0x0001

ffi.cdef[[
typedef struct _LIBSSH2_USERAUTH_KBDINT_PROMPT
{
    char* text;
    unsigned int length;
    unsigned char echo;
} LIBSSH2_USERAUTH_KBDINT_PROMPT;

typedef struct _LIBSSH2_USERAUTH_KBDINT_RESPONSE
{
    char* text;
    unsigned int length;
} LIBSSH2_USERAUTH_KBDINT_RESPONSE;

typedef struct _LIBSSH2_SESSION                     LIBSSH2_SESSION;
typedef struct _LIBSSH2_CHANNEL                     LIBSSH2_CHANNEL;
typedef struct _LIBSSH2_LISTENER                    LIBSSH2_LISTENER;
typedef struct _LIBSSH2_KNOWNHOSTS                  LIBSSH2_KNOWNHOSTS;
typedef struct _LIBSSH2_AGENT                       LIBSSH2_AGENT;

typedef struct _LIBSSH2_SESSION                     LIBSSH2_SESSION;
typedef struct _LIBSSH2_CHANNEL                     LIBSSH2_CHANNEL;
typedef struct _LIBSSH2_LISTENER                    LIBSSH2_LISTENER;
typedef struct _LIBSSH2_KNOWNHOSTS                  LIBSSH2_KNOWNHOSTS;
typedef struct _LIBSSH2_AGENT                       LIBSSH2_AGENT;

typedef int libssh2_socket_t;

const char * libssh2_version(int required_version);

/* LIBSSH2_API */ int libssh2_init(int flags);
/* LIBSSH2_API */ void libssh2_exit(void);
/* LIBSSH2_API */ void libssh2_free(LIBSSH2_SESSION *session, void *ptr);

/* LIBSSH2_API */ int libssh2_session_supported_algs(LIBSSH2_SESSION* session,
                                                     int method_type,
                                                     const char*** algs);

/* Session API */

/* LIBSSH2_API */ LIBSSH2_SESSION *
libssh2_session_init_ex(void *, void *, void *, void *);
///* LIBSSH2_API */ LIBSSH2_SESSION * libssh2_session_init(void);

/* LIBSSH2_API */ void **libssh2_session_abstract(LIBSSH2_SESSION *session);

/* LIBSSH2_API */ void *libssh2_session_callback_set(LIBSSH2_SESSION *session,
                                               int cbtype, void *callback);
/* LIBSSH2_API */ int libssh2_session_banner_set(LIBSSH2_SESSION *session,
                                                 const char *banner);
/* LIBSSH2_API */ int libssh2_banner_set(LIBSSH2_SESSION *session,
                                         const char *banner);

/* LIBSSH2_API */ int libssh2_session_startup(LIBSSH2_SESSION *session, int sock);
/* LIBSSH2_API */ int libssh2_session_handshake(LIBSSH2_SESSION *session,
                                                libssh2_socket_t sock);
/* LIBSSH2_API */ int libssh2_session_disconnect_ex(LIBSSH2_SESSION *session,
                                                    int reason,
                                                    const char *description,
                                                    const char *lang);

/* LIBSSH2_API */ int libssh2_session_free(LIBSSH2_SESSION *session);

/* LIBSSH2_API */ const char *libssh2_hostkey_hash(LIBSSH2_SESSION *session,
                                                   int hash_type);

/* LIBSSH2_API */ const char *libssh2_session_hostkey(LIBSSH2_SESSION *session,
                                                      size_t *len, int *type);

/* LIBSSH2_API */ int libssh2_session_method_pref(LIBSSH2_SESSION *session,
                                                  int method_type,
                                                  const char *prefs);
/* LIBSSH2_API */ const char *libssh2_session_methods(LIBSSH2_SESSION *session,
                                                      int method_type);
/* LIBSSH2_API */ int libssh2_session_last_error(LIBSSH2_SESSION *session,
                                                 char **errmsg,
                                                 int *errmsg_len, int want_buf);
/* LIBSSH2_API */ int libssh2_session_last_errno(LIBSSH2_SESSION *session);
/* LIBSSH2_API */ int libssh2_session_set_last_error(LIBSSH2_SESSION* session,
                                                     int errcode,
                                                     const char* errmsg);
/* LIBSSH2_API */ int libssh2_session_block_directions(LIBSSH2_SESSION *session);

/* LIBSSH2_API */ int libssh2_session_flag(LIBSSH2_SESSION *session, int flag,
                                           int value);
/* LIBSSH2_API */ const char *libssh2_session_banner_get(LIBSSH2_SESSION *session);

/* Userauth API */
/* LIBSSH2_API */ char *libssh2_userauth_list(LIBSSH2_SESSION *session,
                                              const char *username,
                                              unsigned int username_len);
/* LIBSSH2_API */ int libssh2_userauth_authenticated(LIBSSH2_SESSION *session);

/* LIBSSH2_API */ /* int libssh2_userauth_password_ex(LIBSSH2_SESSION *session,
                                                   const char *username,
                                                   unsigned int username_len,
                                                   const char *password,
                                                   unsigned int password_len,
                                                   LIBSSH2_PASSWD_CHANGEREQ_FUNC((*passwd_change_cb)));
						   */

/* LIBSSH2_API */ int
libssh2_userauth_publickey_fromfile_ex(LIBSSH2_SESSION *session,
                                       const char *username,
                                       unsigned int username_len,
                                       const char *publickey,
                                       const char *privatekey,
                                       const char *passphrase);

/* LIBSSH2_API */ /* int
libssh2_userauth_publickey(LIBSSH2_SESSION *session,
                           const char *username,
                           const unsigned char *pubkeydata,
                           size_t pubkeydata_len,
                           LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC((*sign_callback)),
                           void **abstract); */

/* LIBSSH2_API */ int
libssh2_userauth_hostbased_fromfile_ex(LIBSSH2_SESSION *session,
                                       const char *username,
                                       unsigned int username_len,
                                       const char *publickey,
                                       const char *privatekey,
                                       const char *passphrase,
                                       const char *hostname,
                                       unsigned int hostname_len,
                                       const char *local_username,
                                       unsigned int local_username_len);

/* LIBSSH2_API */ int
libssh2_userauth_publickey_frommemory(LIBSSH2_SESSION *session,
                                      const char *username,
                                      size_t username_len,
                                      const char *publickeyfiledata,
                                      size_t publickeyfiledata_len,
                                      const char *privatekeyfiledata,
                                      size_t privatekeyfiledata_len,
                                      const char *passphrase);

/* LIBSSH2_API */ /* int
libssh2_userauth_keyboard_interactive_ex(LIBSSH2_SESSION* session,
                                         const char *username,
                                         unsigned int username_len,
                                         LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(
                                                       (*response_callback))); */

/* LIBSSH2_API */ /* int libssh2_poll(LIBSSH2_POLLFD *fds, unsigned int nfds,
                                      long timeout); */


	typedef int SOCKET;
	typedef unsigned int socklen_t;
	typedef uint16_t u_short;
	typedef uint32_t u_int;
	typedef unsigned long u_long;
	typedef unsigned char byte;
	typedef unsigned long size_t;
	ssize_t read (int , void *, size_t);
	ssize_t write (int , const void *, size_t);


	struct sockaddr {
		unsigned short sa_family;
		char sa_data[14];
	};
	struct in_addr {
		uint32_t s_addr;
	};
	struct sockaddr_in {
		short   sin_family;
		u_short sin_port;
		struct  in_addr sin_addr;
		char    sin_zero[8];
	};
	struct addrinfo {
		int              ai_flags;
		int              ai_family;
		int              ai_socktype;
		int              ai_protocol;
		socklen_t        ai_addrlen;
		struct sockaddr *ai_addr;
		char            *ai_canonname;
		struct addrinfo *ai_next;
	};


	typedef struct hostent {
		char *h_name;
		char **h_aliases;
		short h_addrtype;
		short h_length;
		byte **h_addr_list;
	};
	typedef struct timeval {
		long int tv_sec;
		long int tv_usec;
	};
	typedef struct fd_set {
		u_int fd_count;
		SOCKET  fd_array[64];
	} fd_set;
	u_long htonl(u_long hostlong);
	u_short htons(u_short hostshort);
	u_short ntohs(u_short netshort);
	u_long ntohl(u_long netlong);
	unsigned long inet_addr(const char *cp);
	char *inet_ntoa(struct in_addr in);
	SOCKET socket(int af, int type, int protocol);
	SOCKET accept(SOCKET s,struct sockaddr *addr,int *addrlen);
	int bind(SOCKET s, const struct sockaddr *name, int namelen);
	int close(SOCKET s);
	int connect(SOCKET s, const struct sockaddr *name, int namelen);
	int getsockname(SOCKET s, struct sockaddr *addr, int *namelen);
	int getpeername(SOCKET s, struct sockaddr *addr, int *namelen);
	int ioctl(SOCKET s, long cmd, u_long *argp);
	int listen(SOCKET s, int backlog);
	int recv(SOCKET s, char *buf, int len, int flags);
	int recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen);
	int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
	int send(SOCKET s, const char *buf, int len, int flags);
	int sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
	int shutdown(SOCKET s, int how);
	struct hostent *gethostbyname(const char *name);
	struct hostent *gethostbyaddr(const void *addr, int len, int type);
	int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);

	int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
	int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

	int getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);

	const char *gai_strerror(int errcode);
	char * strerror (int errnum);
	const char *hstrerror(int err);
	extern int __h_errno;
]]



local SOMAXCONN = 128

local INVALID_SOCKET = -1
local INADDR_ANY = 0
local INADDR_NONE = 0XFFFFFFFF

local SOL_SOCKET = 1
local AF_INET = 2
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local SOCKET_ERROR = -1
local SO_REUSEADDR = 2

local SD_RECEIVE = 0
local SD_SEND = 1
local SD_BOTH = 2

local SO_RCVTIMEO = 20
local SO_SNDTIMEO = 21
local FIONBIO = 0x5421

local libssh2 = ffi.load("ssh2")

local VERSION = "0.1.0"

local export = {}

local function version()
    local required_version = 0
    local libssh2_version = libssh2.libssh2_version(required_version)
    return {
        libssh2_version = ffi.string(libssh2_version),
	version = VERSION,
}
end
export.version = version

-- TEST: require("log").info(version())
-- {"libssh2_version":"1.8.0","version":"0.1.0"}

--- Module initialization.
--
-- @return status, boolean
-- @function export.init
local function init(flags)
    local flags = flags or 0
    local rc = libssh2.libssh2_init(flags)
    return rc and true or false
end
export.init = init

-- @return nil
-- @function export.exit
local function exit()
    libssh2.libssh2_exit()
end
export.exit = exit

local function resolve_dns(address)
    local results = ffi.new("struct addrinfo*[1]")
    if ffi.C.getaddrinfo(address, nil, hints, ffi.cast("struct addrinfo **", results)) ~= 0 then
        return nil, ffi.string(ffi.C.gai_strerror(ffi.errno()))
    end

    local host = ffi.new("char[256]")
    if ffi.C.getnameinfo(results[0].ai_addr, results[0].ai_addrlen, host, ffi.sizeof(host), nil, 0, 1) < 0 then
        return nil, strerr()
    end

    return ffi.C.inet_addr(ffi.string(host))
end

local function new_socket()
    local fd = ffi.C.socket(AF_INET, SOCK_STREAM, 0)
    if fd < 0 then
        return nil
    end
    ffi.C.ioctl(fd, FIONBIO, ffi.new("uint64_t[1]", 1))

    return fd
end

local function strerr()
    return ffi.string(ffi.C.strerror(ffi.errno())) .. " ( " .. ffi.errno() .. " ) "
end

local function connect(username, password, hostname, port)
    port = port or 22

    local rc = init()
    if not rc then
        error("libssh2 initialization failed", 2)
    end

    local server_address = ffi.new("struct sockaddr_in[1]", {{
        sin_family = AF_INET,
        sin_addr = {
            s_addr = resolve_dns(hostname),
        },
        sin_port = ffi.C.htons(port),
    }})

    local fd = new_socket()
    if ffi.C.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, ffi.cast("void *", ffi.new("int[1]", b and 1 or 0)), ffi.sizeof(ffi.typeof("int"))) < 0 then
        print(strerr())
    end
    local ret = ffi.C.connect(fd, ffi.cast("const struct sockaddr *", server_address), ffi.sizeof(server_address[0]))
    if ret < 0 then
        print(strerr())
	-- TODO: ignore EINPROGRESS
	--error("Failure connecting to remote host: " .. strerr(), 2)
    end
    address = server_address[0]

    -- Create a session instance and start it up. This will trade welcome
    -- banners, exchange keys, and setup crypto, compression, and MAC layers.
    local session = libssh2.libssh2_session_init_ex(ffi.NULL, ffi.NULL, ffi.NULL, ffi.NULL)
    --local session = libssh2.libssh2_session_init()
    if session == nil then
        error("Failure initialize session", 2)
    end
    if libssh2.libssh2_session_handshake(session, fd) then
        error("Failure establishing SSH session", 2)
    end

    local fingerprint = libssh2.libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1)
    print("Fingeprint:", fingerprint)

    -- Check what authentication methods are available.
    local userauthlist = libssh2.libssh2_userauth_list(session, username, #username)
    print("Authentication methods:", userauthlist)

    --[[
    if(strstr(userauthlist, "password") != NULL) {
        auth_pw |= 1;
    }
    if(strstr(userauthlist, "keyboard-interactive") != NULL) {
        auth_pw |= 2;
    }
    if(strstr(userauthlist, "publickey") != NULL) {
        auth_pw |= 4;
    }

    /* if we got an 4. argument we set this option if supported */
    if(argc > 4) {
        if((auth_pw & 1) && !strcasecmp(argv[4], "-p")) {
            auth_pw = 1;
        }
        if((auth_pw & 2) && !strcasecmp(argv[4], "-i")) {
            auth_pw = 2;
        }
        if((auth_pw & 4) && !strcasecmp(argv[4], "-k")) {
            auth_pw = 4;
        }
    }

    if(auth_pw & 1) {
        /* We could authenticate via password */
        if(libssh2_userauth_password(session, username, password)) {

            fprintf(stderr, "\tAuthentication by password failed!\n");
            goto shutdown;
        }
        else {
            fprintf(stderr, "\tAuthentication by password succeeded.\n");
        }
    }
    else if(auth_pw & 2) {
        /* Or via keyboard-interactive */
        if(libssh2_userauth_keyboard_interactive(session, username,

                                                 &kbd_callback) ) {
            fprintf(stderr,
                    "\tAuthentication by keyboard-interactive failed!\n");
            goto shutdown;
        }
        else {
            fprintf(stderr,
                    "\tAuthentication by keyboard-interactive succeeded.\n");
        }
    }
    else if(auth_pw & 4) {
        /* Or by public key */
        if(libssh2_userauth_publickey_fromfile(session, username, keyfile1,

                                               keyfile2, password)) {
            fprintf(stderr, "\tAuthentication by public key failed!\n");
            goto shutdown;
        }
        else {
            fprintf(stderr, "\tAuthentication by public key succeeded.\n");
        }
    }
    else {
        fprintf(stderr, "No supported authentication methods found!\n");
        goto shutdown;
    }
    ]]
    exit()
end

--connect("root", "1q2w3e", "gw.bronevichok.ru")
connect("root", "1q2w3e", "79.164.223.111")

return export

--[[
    /* Request a shell */
    channel = libssh2_channel_open_session(session);

    if(!channel) {
        fprintf(stderr, "Unable to open a session\n");
        goto shutdown;
    }

    -- Some environment variables may be set, it's up to the server which ones
    -- it'll allow though.
    libssh2_channel_setenv(channel, "FOO", "bar");

    -- Request a terminal with 'vanilla' terminal emulation.
    -- See /etc/termcap for more options.
    if(libssh2_channel_request_pty(channel, "vanilla")) {
        fprintf(stderr, "Failed requesting pty\n");
        goto skip_shell;
    }

    -- Open a SHELL on that PTY.
    if(libssh2_channel_shell(channel)) {
        fprintf(stderr, "Unable to request shell on allocated pty\n");
        goto shutdown;
    }

    /* At this point the shell can be interacted with using
     * libssh2_channel_read()
     * libssh2_channel_read_stderr()
     * libssh2_channel_write()
     * libssh2_channel_write_stderr()
     *
     * Blocking mode may be (en|dis)abled with: libssh2_channel_set_blocking()
     * If the server send EOF, libssh2_channel_eof() will return non-0
     * To send EOF to the server use: libssh2_channel_send_eof()
     * A channel can be closed with: libssh2_channel_close()
     * A channel can be freed with: libssh2_channel_free()
     */

  skip_shell:
    if(channel) {
        libssh2_channel_free(channel);

        channel = NULL;
    }

    /* Other channel types are supported via:
     * libssh2_scp_send()
     * libssh2_scp_recv2()
     * libssh2_channel_direct_tcpip()
     */

  shutdown:

    libssh2_session_disconnect(session, "Normal Shutdown, Thank you for playing");
    libssh2_session_free(session);
]]
