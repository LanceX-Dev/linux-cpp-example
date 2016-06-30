//====================================================================================
//     The MIT License (MIT)
//
//     Copyright (c) 2011 Kapparock LLC
//
//     Permission is hereby granted, free of charge, to any person obtaining a copy
//     of this software and associated documentation files (the "Software"), to deal
//     in the Software without restriction, including without limitation the rights
//     to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//     copies of the Software, and to permit persons to whom the Software is
//     furnished to do so, subject to the following conditions:
//
//     The above copyright notice and this permission notice shall be included in
//     all copies or substantial portions of the Software.
//
//     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//     IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//     FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//     AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//     LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//     OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//     THE SOFTWARE.
//====================================================================================

#include "router.hpp"
#include <syslog.h>
#include <sys/file.h>
#include <sys/un.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <semaphore.h>
#include <dirent.h>
#include <stdlib.h>
#include <netdb.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <syslog.h>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

namespace lancex 
{
    namespace tags
	{
		namespace header
		{
			const char tod[] = "tod";
			const char seq[] = "seqNum";
			const char cmd[] = "type";
			const char mac[] = "mac";
			const char dat[] = "data";
		}
		namespace payload
		{
			const char status[] = "status";
			const char authKey[] = "authKey";
			const char devTkn[]	= "deviceToken";
			const char devSta[]	= "deviceStatus";
			const char message[] = "rpcMessage";
			const char rpcMsg[]	= "rpcMessage";
		}
	}
    
    char* ABSOLUTE_USER_FILE_PATH;
    char* ABSOLUTE_CREDENTIAL_PATH;
    char* ABSOLUTE_CERT_PATH;
    
    int openUnixServerSock(const char *name, const char *service);
    int openUnixClientSock(const char *name, const char *service);
    std::string recvStr(int fd);
	struct UnixSocketServelet
	{
		sockaddr_in cliaddr_{};
		socklen_t 	cliAddrLen_	{};
		std::string args_{};
		int fd_	{-1};
		UnixSocketServelet(int svrfd) {
			fd_ = accept(svrfd, (struct sockaddr *)&cliaddr_, &cliAddrLen_);
		}
		UnixSocketServelet()
		{}
		~UnixSocketServelet() {
			if (fd_ > 0) close(fd_);
		}

		int send(const std::string s)
		{
			return ::send(fd_, s.c_str(), s.size(), 0);
		}

		int recv(char* b, size_t s)
		{
			return ::recv(fd_ ,b, s, 0);
		}

		int fd() const
		{
			return fd_;
		}

		std::string& args()
		{
			return args_;
		}
		void args(std::string&& a) {
			args_ = move(a);
		}
	};
	using spUnixSocketServelet = std::shared_ptr<UnixSocketServelet>;
    class Conn {
	public:
		virtual int fd() const = 0;
		virtual void cb() = 0;
		virtual ~Conn() {}
	};
	class UDPConn {
	private:
		int fd_ {-1};
		addrinfo *ai_ {NULL};
		sockaddr_in cliaddr {};
		socklen_t len_{};
		std::string name_;
		std::string service_;
		int	rt_{-1};
		time_t initTime {time(NULL)};
		void freeResrc();
		void acqrResrc();
	public:
		UDPConn()= delete;
		UDPConn(const char* ip, const char* port):UDPConn{ip,port,-1}
		{}
		UDPConn(const char* ip, const char* port, int rt)
		:name_{ip},service_{port},rt_{rt}
		{
			acqrResrc();
		}
		~UDPConn() 
        {
			freeResrc();
		}
		void reset() 
        {
			freeResrc(); acqrResrc();
		}
		int	socketFd() const 
        {
			return fd_;
		}
		int	sendto(const char* b, size_t s) 
        {
			return ::sendto(fd_, b, s, 0, ai_->ai_addr, ai_->ai_addrlen);
		}
		int	sendto(const std::string& str) 
        {
			return sendto(str.c_str(),str.size());
		}
		int	recvfrom(char* b, size_t s) 
        {
			return ::recvfrom(fd_,	b, s, 0 , (sockaddr *)&cliaddr, &len_);
		}
		int	uptime() const 
        {
			return time(NULL) - initTime;
		}
		int	fd() const 
        {
			return fd_;
		}
		void cb() {}
	};// class UDPConn
    
    class selects
	{
	private:
		using pair_ = std::pair<int,std::function<void()>>;
		fd_set 	rdset_{};
		timeval tv{};
		std::vector<pair_> conns{};
		int fdMax{0};
	public:
		selects()= delete;
		selects(__time_t sec, __suseconds_t usec = 0):tv{sec,usec}
		{}
		void reset();
		void rFD_SET(int fd, std::function<void()> cb);
		void listenOnce();
		~selects(){}
	}; // class selects

	class selectws
	{
	private:
		using pair_ = std::pair<int,std::function<void()>>;
		fd_set rdset_{};
		timeval tv{};
		std::vector<pair_> conns{};
		int fdMax{0};
	public:
		selectws() = delete;
		selectws(int sec, int usec = 0):tv{sec,usec}
		{}
		void reset();
		void wFD_SET(int fd, std::function<void()> cb);
		void listenOnce();
		~selectws(){}
	}; 

	class sslCliConn
	{
	private:
		SSL* ssl {nullptr};
		std::string buf_{};
	public:
		sslCliConn(const char* IP, const char* port, int rt, SSL_CTX *ctx);
		~sslCliConn();
		int send(const char* b, size_t s);
		int send(const std::string& s) { return send(s.c_str(), s.size());}
		int recv(char* b, size_t s);
		std::string& recvStr();
		int fd() const;
	};
    void *startUDPServer000(void *td);
    
    struct {
        std::string ip ;
        std::string tcp;
        std::string udp;
    } apiServer; 
}

namespace lancex 
{
    string recvStr(int fd) {
		string out;
		static const int maxlen = 4096;
		char x[maxlen];
		int l = 0;

		struct pred {
			int maxLen_;
			int fd_;
			pred(int m, int fd):maxLen_{m},fd_{fd}{}
			bool operator()(int l) {
				if (l <= 0 || l < maxLen_) return false;
				char b[1];
				return recv(fd_, b, 1, MSG_PEEK|MSG_DONTWAIT) > 0;
			}
		};

		pred fn{maxlen, fd};
		do {
			l = recv(fd, x, maxlen,0);
			out.append(x,l);
		} while(fn(l));
		return out;
	}

	int open_sock_(const char* name, const char* service, addrinfo **result, int fm, int st, int fl)
	{
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = fm;
		hints.ai_socktype = st;
		hints.ai_flags = fl;
		if (getaddrinfo(name,service, &hints, result) < 0) {
			syslog(LOG_INFO,"getaddrinfo failed %s", strerror(errno));
			return -1;
		}
		int socketfd = socket((*result)->ai_family, (*result)->ai_socktype, (*result)->ai_protocol);
		if (socketfd < 0) {
			syslog(LOG_INFO,"socket() open failed: %s", strerror(errno));
			close(socketfd);
			return -1;
		}
		int flags = fcntl(socketfd, F_GETFL, 0);
		fcntl(socketfd, F_SETFL, flags | O_NONBLOCK);
		int on=1;
		setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
		return socketfd;
	}

	inline int openUDPSock(const char* name, const char* service, addrinfo **result)
	{
		return open_sock_(name, service, result,AF_INET,SOCK_DGRAM,AI_PASSIVE );
	}

	void UDPConn::freeResrc() {
		if (fd_ > 0) close(fd_);
		if (ai_!=NULL) freeaddrinfo(ai_);
	}
	void UDPConn::acqrResrc() {
		const char* cn = name_.size() == 0 ? NULL : name_.c_str();
		const char* cs = service_.size() == 0 ? NULL : service_.c_str();
		while ((fd_=openUDPSock(cn, cs, &ai_)) < 0 && rt_ > 0)
		{
			lancex::Sleep(rt_);
			syslog(LOG_INFO, "open UDP port failed, retry in %d secs...", rt_);
		}
	}

	void selects::reset() {
		FD_ZERO(&rdset_);
		conns.clear();
		fdMax=0;
	}
	void selects::rFD_SET(int fd, function<void()> cb) {
		FD_SET(fd, &rdset_);
		conns.emplace_back(fd,move(cb));
		fdMax = fd > fdMax ? fd : fdMax;
	}
	void selects::listenOnce(){
		int retVal;
		timeval tv_ = tv;
		fd_set rdset__ = rdset_;

		do {
			retVal = select(fdMax+1, &rdset__, NULL, NULL, &tv_);
		} while (retVal < 0 && errno == EINTR && tv_.tv_usec != 0 && tv_.tv_sec!=0);

		if (retVal > 0)	{
			for (auto& x : conns) {
				if (FD_ISSET(x.first,&rdset_)) x.second();}
		}
	}

	int openTCP(const char *hostname, const char *port)
	{
		addrinfo *result;
		int socketfd = open_sock_(hostname, port, &result,AF_INET,SOCK_STREAM,AI_PASSIVE );
		if (socketfd < 0)
		{
			freeaddrinfo(result);
			syslog(LOG_INFO,"socket() open failed: %s", strerror(errno));
			close(socketfd);
			return -1;
		}

		connect(socketfd,result->ai_addr,result->ai_addrlen);

		fd_set wrset;
		timeval tv = {5,0};
		FD_ZERO(&wrset);
		FD_SET(socketfd, &wrset);
		int retVal = 0;
		do {
			retVal = select(socketfd+1, NULL, &wrset, NULL, &tv);
		} while (retVal < 0 && errno == EINTR && tv.tv_usec != 0 && tv.tv_sec!=0);

		if (retVal <= 0)
		{
			return -1;
		}

		int so_error;
		socklen_t slen = sizeof so_error;
		getsockopt(socketfd, SOL_SOCKET, SO_ERROR, &so_error, &slen);
		if (so_error == 0)
		{
			freeaddrinfo(result);
			return socketfd;
		} else {
			freeaddrinfo(result);
			syslog(LOG_INFO,"connection failed");
			close(socketfd);
			return -1;
		}
	}
	int sslWaitOn(SSL *ssl, int timeoutSec, int(*fn)(SSL* ssl))
	{
		int status = fn(ssl);
		int sslerr = 0;
		if (status < 0) {
			sslerr = SSL_get_error(ssl, status);
		}

		if (status >= 0 || (sslerr != SSL_ERROR_WANT_READ && sslerr != SSL_ERROR_WANT_WRITE))
		{
			return status;
		}

		int timeoutuSec = timeoutSec * 1000000;
		int timeuSecAcc = 0;
		timespec tv = {0, 10000000};

		while (status < 0 && timeuSecAcc < timeoutuSec)
		{
			status = fn(ssl);
			timeuSecAcc += 10000;
			lancex::NanoSleep(&tv);
		}

		if (status < 0)
		{
			sslerr = SSL_get_error(ssl, status);
			syslog(LOG_INFO,"sslerr %d, timeAcc %d", sslerr, timeuSecAcc);
		}
		return status;
	}

	SSL* openSSLConn(const char* IP, const char* port, SSL_CTX *ctx)
	{
		int fd_ = openTCP(IP, port);
		if (fd_ < 0) return NULL;

		SSL* ssl = SSL_new(ctx);
		SSL_set_fd(ssl,fd_);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
		if ( sslWaitOn(ssl, 15, SSL_connect) >= 0)
		{
			long verify = SSL_get_verify_result(ssl);
			if(verify == X509_V_OK)
			{
				if (sslWaitOn(ssl, 15, SSL_do_handshake) >= 0)
				{
					return ssl;
				} else {
					syslog(LOG_INFO, "sslWaitOn(ssl, 15, SSL_do_handshake) failed");
				}
			} else {
				syslog(LOG_INFO, "SSL_get_verify_result(ssl) failed, stat = %ld", verify);
			}
		} else {
			syslog(LOG_INFO, "sslWaitOn(ssl, 15, SSL_connect)");
		}

		close(fd_);
		SSL_free(ssl);

		return NULL;
	}

	sslCliConn::sslCliConn(const char* IP, const char* port, int rt, SSL_CTX *ctx)
	{
		while ((ssl = openSSLConn(IP, port, ctx)) == NULL && rt > 0) {
			syslog(LOG_INFO, "giving up this connection, retry in %d secs", rt);
			lancex::Sleep(rt);
		}
	}

	sslCliConn::~sslCliConn()
	{
		if (ssl != NULL)
		{
			int fd = SSL_get_fd(ssl);
			SSL_shutdown(ssl);
			close(SSL_get_fd(ssl));
			SSL_free(ssl);
		}
	}

	int sslCliConn::send(const char* b, size_t s)
	{
		int err_code = 0;
		int SSL_write_len = -1;
		do {
			SSL_write_len = SSL_write(ssl,b,s);
			if (SSL_write_len < 0 )
			{
				err_code = SSL_get_error(ssl, SSL_write_len);
			}
		} while (err_code==SSL_ERROR_WANT_WRITE && SSL_write_len < 0 );
		return SSL_write_len;
	}

	int sslCliConn::recv(char* b, size_t s)
	{
		SSL_read(ssl, b, s);
	}

	string& sslCliConn::recvStr() {
		const int maxLen = 16384;
		int bufLen = 0,	blkLen = 0,	err_code = 0;
		char b_[maxLen];
		do {
			blkLen = SSL_read(ssl,b_ + bufLen,maxLen);
			if (blkLen <= 0) {
				err_code = SSL_get_error(ssl, blkLen);
			} else {
				b_[blkLen] = 0;
				buf_.append(b_);
			}
		} while (blkLen == maxLen || (blkLen <= 0 && (err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE)));
		return buf_;
	}
	int sslCliConn::fd() const
	{
		return SSL_get_fd(ssl);
	}
    
    std::map<string,map<string,Handlers>> __handlers_repository;
	Handlers& __container(const string& e, const string& u)
	{
		return __handlers_repository[e][u];
	}
	
    int openUnixServerSock(const char *name, const char *service)
    {
	   struct sockaddr_un local;
	   int len;
	   int on = 1;

	   int socketfd = socket(PF_UNIX,SOCK_STREAM, 0);
	   if (socketfd < 0)
	   {
		  syslog(LOG_INFO,"socket() open failed: %s", strerror(errno));
		  close(socketfd);
		  return -1;
	   }
	   memset(&local, 0, sizeof(struct sockaddr_un));
	   local.sun_family = AF_UNIX;
	   strcpy(local.sun_path, service);
	   unlink(local.sun_path);
	   len = strlen(local.sun_path) + sizeof(local.sun_family);

	   int flags = fcntl(socketfd, F_GETFL, 0);
	   fcntl(socketfd, F_SETFL, flags | O_NONBLOCK);

	   setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));

	   if (bind(socketfd, (struct sockaddr *)&local, sizeof(struct sockaddr_un)) <0)
	   {
		  syslog(LOG_INFO,"bind() failed with service  : %s , for reason : %s", service, strerror(errno));
		  close(socketfd);
		  return -1;
	   }

	   return socketfd;
}


int openUnixClientSock(const char *name, const char *service)
{
	struct sockaddr_un local;
	int len;
	int on = 1;

	int socketfd = socket(PF_UNIX,SOCK_STREAM, 0);
	if (socketfd < 0)
	{
		syslog(LOG_INFO,"socket() open failed: %s", strerror(errno));
		close(socketfd);
		return -1;
	}
	memset(&local, 0, sizeof(struct sockaddr_un));
	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, service);
	len = strlen(local.sun_path) + sizeof(local.sun_family);

	int flags = fcntl(socketfd, F_GETFL, 0);
	fcntl(socketfd, F_SETFL, flags | O_NONBLOCK);
	setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));

	int status = connect(socketfd,(struct sockaddr *)&local, len);

	fd_set fdset;
	FD_ZERO(&fdset);
	FD_SET(socketfd, &fdset);

	struct timeval tv;
	tv.tv_sec = 1;

	int retVal;

	do {
			retVal = select(socketfd+1, NULL, &fdset, NULL, &tv);
	} while (retVal < 0 && errno == EINTR && tv.tv_usec != 0 && tv.tv_sec!=0);

	if (retVal == 1)
	{
		int so_error;
		socklen_t slen = sizeof so_error;
		getsockopt(socketfd, SOL_SOCKET, SO_ERROR, &so_error, &slen);
		if (so_error == 0)
		{
			return socketfd;
		} else
		{
			syslog(LOG_INFO,"connection failed");
			close(socketfd);
			return -1;
		}
	} else {
		syslog(LOG_INFO,"no socket, return from select() = %d", retVal);
		close(socketfd);
		return -1;
	}

	return -1;
}
}
namespace lancex {
	char hwAddr[13];
	sem_t *sslChannelSem;

	int getMACAddr()
	{
		struct ifreq ifr;
		char iface[] = "wlan0";
		int fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
		ioctl(fd, SIOCGIFHWADDR, &ifr);
		close(fd);
		unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
		sprintf(hwAddr, "%02x%02x%02x%02x%02x%02x",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		return 0;
	}

	SSL_CTX *ctx;

	int CTXInit()
	{
		/* Set up the SSL context */
		ctx = SSL_CTX_new(TLSv1_2_client_method());
		/* Load the trust store */
		if(! SSL_CTX_load_verify_locations(ctx, ABSOLUTE_CERT_PATH, NULL))
		{
			fprintf(stderr, "Error loading trust store\n");
			ERR_print_errors_fp(stderr);
			SSL_CTX_free(ctx);
			return -1;
		}

		if (ctx == NULL) {
			ERR_print_errors_fp(stderr);
			LOG_ERROR_MESSAGE("failed to obtain ctx");
			return -1;
		}
		return 0;
	}
}
namespace lancex {

	void* hostUNIXSocketServer(void *td)
	{
		int fd = openUnixServerSock(NULL, USOCKETPATH);
		if (fd < 0) {
			LOG_ERROR_MESSAGE("openUnixServerSock failed");
			return nullptr;
		}

		if (listen(fd, 128) < 0) {
			LOG_ERROR_MESSAGE("listen() failed in UNIXServerSock");
			return nullptr;
		}

		selects s{60};

		s.rFD_SET(fd, [fd]() {
			UnixSocketServelet svr(fd);
			if (svr.fd() < 0) {
				return;
			}

			lancex::JSON req{ recvStr(svr.fd()) };
			if (!req.good())
			{
				return;
			}

			if (req.exist("ver") && req["ver"].toString() == "0001") /*RESTful mode*/
			{
				string rsp{"[\"success\"]"};
				handleRESTful(req["request"].toString(), rsp);
				svr.send(rsp);
			}
		});
		while (1) {
			s.listenOnce();
		}
		close(fd);
		return nullptr;
	}
}
namespace lancex {
	class cbContext {
	public:
		virtual void response(const string&) = 0;
		virtual const string& args() = 0;
		virtual ~cbContext() {}
	};
	using cbContextRef = cbContext&;

	namespace credentials {
		using JSON = lancex::JSON;
		using namespace lancex::tags;

		bool remoteAccessIsEnabled() {
			return JSON(ABSOLUTE_CREDENTIAL_PATH)["connect"].toInteger() == 1;
		}
		std::string	deviceToken() {
			return JSON(ABSOLUTE_CREDENTIAL_PATH)[payload::devTkn].toString();
		}
	} // namespace credentials

	namespace message_payloads
	{
		using JSON = lancex::JSON;
		using namespace credentials;
		using namespace lancex::protocol::ver2;
		using namespace lancex::protocol::ver2::uri_labels;
		struct cbCtx : public cbContext
		{
			string msg_;
			cbCtx(const string& msg):msg_{msg} {}
			cbCtx(string&& msg):msg_{move(msg)}{}
			const string& args() 	{return msg_;}
			void  response(const string& s) {}
			~cbCtx(){}
		};
		using cbCtxRef = cbCtx&;
		struct onePing_ {
			int lastReq_{0};
			int lastRsp_{0};
			int minReqIntv_{};
			int minRspIntv_{};
			int bii_{}; // broken link indicator
			int seq_{0};
			void operator()(UDPConn& conn) {
				if ((time(0) - lastReq_) < minReqIntv_)
				{
					return;
				}

				JSON pl_ = req_struct(pingreq);
				pl_[ARG][token] = deviceToken();
				pl_[ARG][wantrsp] = ((time(0) - lastRsp_) > minRspIntv_);

				if (((time(0) - lastRsp_) > minRspIntv_))
				{
					syslog(LOG_INFO, "sending ping..., last good : %ld secs ago", time(0) - lastRsp_);
				}

				lastReq_ = time(0);
				conn.sendto(pl_.stringify());
			}
			onePing_(int minReqIntv_, int minRspIntv_, int bii)
			:minReqIntv_{minReqIntv_},minRspIntv_{minRspIntv_},bii_{bii}
			{
				lancex::simpleHandler(pingrsp, [this](cbCtxRef x) {
					lastRsp_ = time(0);
				});
			}
			bool brokenLink() {return (time(NULL) - lastRsp_ - minRspIntv_> bii_);}
		}; // struct onePing_

		void getMsg(cbCtxRef x)
		{
			using JSON = lancex::JSON;
			using namespace lancex::protocol::ver2;

			JSON pkt = req_struct("msg/req");
			pkt[ARG] = x.args();
			sslCliConn cli{apiServer.ip.c_str(), apiServer.tcp.c_str(), 5,ctx };
			cli.send(pkt.stringify());
			selects S{2};
			S.rFD_SET(cli.fd(),[&cli](){
				JSON msg{cli.recvStr()};
				class forwardCtx_t : public cbContext
				{
				public:
					string arg_;
					sslCliConn* pCli_;
					forwardCtx_t(string&& a, sslCliConn* pCli) : arg_{a}, pCli_{pCli} {}
					void response(const string& s) override {
						JSON x = req_struct("msg/rsp", s);
						pCli_->send(x.stringify());
					}
					const string& args() override { return arg_;}
					~forwardCtx_t() {}
				};
				forwardCtx_t fx{msg["arg"].toString(), &cli};
				simpleTrigger(msg[ "uri" ].toString(), static_cast<cbContextRef>(fx));
			});
			S.listenOnce();
		}
		void handleRestful(cbContextRef ctx_) {
			string rsp;
			handleRESTful(ctx_.args(), rsp);
			ctx_.response(rsp);
		}

        using namespace lancex::protocol::ver2::uri_labels;
		void sign_in_handle(Context C)
		{
            
//            std::cout << apiServer.ip << ':' << apiServer.tcp << '\n';
//            return;
			sslCliConn cli{apiServer.ip.c_str(), apiServer.tcp.c_str(), 5,ctx };

			JSON pl{C.parameter()};
			JSON req{C.request()};
			JSON response{JSONType::JSON_OBJECT};
			response["status"] = -1;

			if (req["method"].toString() == "POST") {
				pl["mac"] = hwAddr;
				cli.send(req_struct("sign_in/req", pl.stringify()).stringify());

				// TODO: move timeout value to a seperate file
				selects s(2);

				s.rFD_SET(cli.fd(),[&cli, &pl, &response](){
					JSON rsp{JSON{cli.recvStr()}["arg"].toString()};
					if (rsp["status"].toInteger() !=0)
					{
						return;
					}
					JSON task{JSONType::JSON_OBJECT};
					task["email"] = pl["email"];
					task["authkey"] = rsp["authKey"];
					JSON devData{JSONType::JSON_OBJECT};
					devData["deviceToken"] = rsp["deviceToken"];
					devData["authorizedUser"] = move(task);
					devData["connect"] = 1;
					devData.toFile(ABSOLUTE_CREDENTIAL_PATH);
					JSON cred{ABSOLUTE_CREDENTIAL_PATH};
					response["authorized"] = cred["authorizedUser"];
					response["status"] = 0;
				});
				s.listenOnce();
			} else if (req["method"].toString() == "DELETE") {
				unlink(ABSOLUTE_CREDENTIAL_PATH);
				response["status"] = 0;
			} else if (req["method"].toString() == "GET") {
				response["status"] = 0;
				JSON cred{ABSOLUTE_CREDENTIAL_PATH};
				response["authorized"] = cred["authorizedUser"];
			}
			C.response(response.stringify());
		}

		void init()
		{
			simpleHandler("msg/ind" , getMsg);
			simpleHandler("restful/req" , handleRestful);
			handler(EventTag, "sign_in" , sign_in_handle);
		}
	}// namespace message_payloads

	namespace internal {
	}
} 
namespace lancex {
	void *startUDPServer000(void *td) {
		using namespace lancex::credentials;
		using namespace lancex::message_payloads;
		using namespace lancex::internal;

		// it will be better if were loaded from a JSON file
		UDPConn server{apiServer.ip.c_str(), apiServer.udp.c_str(), 10};
		selects S{10};
		onePing_ onePing{10, 3600, 900};
		while(1)
		{
			// *		*			*  WARNINIG		*			*			*
			// this check of enable should be moved somewhere else
			// what if it was disabled when the connection is still open??
			if (!remoteAccessIsEnabled()) {
				lancex::Sleep(5); continue;
			}

			if (onePing.brokenLink()) {
				server.reset();
				S.reset();
				S.rFD_SET(server.socketFd(), [&server]() {
					char b[MAX_SOCKET_BUFFER];
					if (server.recvfrom(b, MAX_SOCKET_BUFFER) > 0) {
						JSON x{b};
						x.toFile("/tmp/justarrive");
						cbCtx f{x[ ARG ].toString()};
						simpleTrigger(x[ URI ].toString(),f);
					}
					return;
				});
			}
			onePing(server);
			S.listenOnce();
		}
		return nullptr;
	}
}
namespace lancex {
	using namespace std;
	std::vector<__Context> __Contexts;
	__Context::__Context(std::string uri):uri_(uri)	{}
	__Context::~__Context(){}
	std::string& __Context::URI() {return uri_;}
	std::string& __Context::parameter() {return parameter_;}
	void __Context::parameter(string P) {parameter_ = P;}
	void __Context::response(string&& R) {response_ = R;}
	void __Context::response(const string& R) {response_ = R;}
	string& __Context::response() {return response_;}
	void __Context::request(const string& S) { request_ = S;}
	string& __Context::request() {return request_;}

	Context getContext(const std::string& uri)
	{
		for (Context x : __Contexts) {if (x.URI() ==  uri) return x;}
		__Contexts.emplace_back(uri);
		return getContext(uri);
	}

	void handleRESTful(const string& req, std::string& rsp) {
		lancex::JSON req_(req);
		lancex::JSON& path  = req_["path"];
		lancex::JSON& param = req_["parameter"];
		std::string uri;

		path.forEachInArr([&](size_t index, lancex::JSON& json){uri += json.toString() + "/";});

		uri.pop_back();
		Context c = getContext(uri);
		c.parameter(param.stringify());
		c.request(req);
		lancex::trigger("Application", uri,  c);
		rsp = c.response();
	}

}
namespace lancex {
    void localIntfInit() {
	   pthread_t thread;
	   pthread_create(&thread, NULL, &hostUNIXSocketServer, NULL);
	   pthread_detach(thread);
    }
    
    string localRpcRequest(const string& in) 
    {
        string out{};
        int fd = openUnixClientSock(NULL, USOCKETPATH);
        if (fd < 0) {
            out.append("failed to open usocket");
            return out;
        }
        send(fd, in.c_str(), in.size(), 0);
        selects s{5};
        s.rFD_SET(fd,[fd, &out]() {
            out = move(recvStr(fd));
        });
        s.listenOnce();

        close(fd);
        return out;
    }
    
    void remoteIntfInit() 
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        SSL_load_error_strings();

        CTXInit();
        getMACAddr();
        sslChannelSem = (sem_t *)malloc(sizeof(sem_t));
        sem_init(sslChannelSem, 0, 1);

        pthread_t thread;
        pthread_create(&thread, NULL, startUDPServer000, (void *)NULL);
        pthread_detach(thread);

        lancex::message_payloads::init();
        return;
    }
    
    void setPaths()
    {
        std::stringstream ss;
        if (USER_FILE_PATH[0] == '~') {
            ss << getenv("HOME") << '/' << USER_FILE_PATH+1 ;
        } else
        {
            ss << USER_FILE_PATH;
        }
                
        ABSOLUTE_USER_FILE_PATH = new char[ss.str().length()+1];
        ABSOLUTE_USER_FILE_PATH[ss.str().length()] = 0;
        ss.str().copy(ABSOLUTE_USER_FILE_PATH,ss.str().length(), 0);
        
        ss.str("");
        ss << ABSOLUTE_USER_FILE_PATH << '/' << CERT_FILE;
        ABSOLUTE_CERT_PATH = new char[ss.str().length()+1];
        ABSOLUTE_CERT_PATH[ss.str().length()] = 0;
        ss.str().copy(ABSOLUTE_CERT_PATH,ss.str().length(), 0);
        
        ss.str("");
        ss << ABSOLUTE_USER_FILE_PATH << '/' << CREDENTIAL_FILE;
        ABSOLUTE_CREDENTIAL_PATH = new char[ss.str().length()+1];
        ABSOLUTE_CREDENTIAL_PATH[ss.str().length()] = 0;
        ss.str().copy(ABSOLUTE_CREDENTIAL_PATH,ss.str().length(), 0);
    }
    
    void getServerInfo()
    {
        char buffer[8192];
        std::string result = "";
        std::stringstream cmdss;
        cmdss << "curl -sS " << QUERY_URL;
        std::shared_ptr<FILE> pipe(popen(cmdss.str().c_str(), "r"), pclose);
        
        while (!feof(pipe.get())) 
        {
            if (fgets(buffer, 8192, pipe.get()) != NULL)
                result += buffer;
        }
        
        JSON info{result};
        apiServer.ip = info["servers"][0][0].toString();
        apiServer.tcp = info["servers"][0][1].toString();
        apiServer.udp = info["servers"][0][2].toString();
        
        ifstream certFile(ABSOLUTE_CERT_PATH);
        if (!certFile) {
            cmdss.str("");
            cmdss << "mkdir -p "<< ABSOLUTE_USER_FILE_PATH;
            system(cmdss.str().c_str());
        
            cmdss.str("");
            cmdss << "echo \"" << info["cert"].toString() << "\" > " << ABSOLUTE_CERT_PATH;
            system(cmdss.str().c_str());
        }
    }
    
    void bindDevice() 
    {
        ifstream credentialFile(ABSOLUTE_CREDENTIAL_PATH);
        if (credentialFile) {
            return;
        }
        
        
        int status = -1, retries = 0;
        
        do {
            std::string email, password;
            // ask for login credential
            
            std::cout << '\n';
            std::cout << "Please enter login email:";
            std::cin >> email;
            std::cout << "Please enter login password:";
            std::cin >> password;
            std::cout << '\n';
            
            lancex::JSON query{lancex::JSONType::JSON_OBJECT} ;
            lancex::JSON request{lancex::JSONType::JSON_OBJECT} ;
        
            request["method"] = "POST";
            request["path"] = lancex::JSON{lancex::JSONType::JSON_ARRAY};
            request["path"].newElement() = "sign_in";
            request["parameter"]["email"] = email;
            request["parameter"]["password"] = password;
        
            query["request"] =  request.stringify();
            query["ver"] = "0001";
            
            lancex::JSON rsp{localRpcRequest(query.stringify())};
            
            status = rsp["status"].toInteger();
            retries++;
            
            if (status == -1 && retries < 3 ) {
                cout << "sign in failed, try again ... \n";
            }
        } while( status == -1 && retries < 3);
        
        if (status == -1) {
            cout << "Sign in failed after 3 retries, exiting." << '\n';
            exit(-1);
        } else {
            cout << "Signed in successfully!" << '\n';
        }
    }
    
    void init() 
    {
        setPaths();
        getServerInfo();
        localIntfInit();
        remoteIntfInit();
        bindDevice();
    }
}

namespace lancex { // helper functions
    int NanoSleep(struct timespec *_interval)
    {
        struct timespec interval, remaining;

        interval = *_interval;
        remaining = *_interval;
        size_t count = 0;

        while(nanosleep(&interval,&remaining)!=0 && count < 0xffffffff)
        {
            interval = remaining;
            count++;
        }

        return count<0xffffffff?0:-1;
    }

    int Sleep(size_t interval)
    {
        struct timespec _interval = {static_cast<__time_t>(interval),0};
        return NanoSleep(&_interval);
    }

    using namespace std;
	JSON::JSON(const JSON& J)
	:JSON()
	{
		json_error_t error;
		json_t * __json =json_deep_copy(J.json_); // make a fresh copy of json
		if (__json) reset(__json);
		else { setFailBit(std::string(const_cast<char*>(error.text))); type_ = JSONType::JSON_FAULT;}
	}

	JSON::JSON(const char* source, JsonSourceType type)	:JSON(source)
	{ }

	JSON::JSON(const char* source):JSON()
	{
		json_error_t error;
		json_t * __json = json_loads( source, JSON_DISABLE_EOF_CHECK, &error);
		if ( __json == NULL )
			if ( (__json = json_load_file(source,JSON_DISABLE_EOF_CHECK, &error)) == NULL )
			{
				setFailBit("Unable to parse JSON");
				type_=JSONType::JSON_FAULT;
				return;
			}
		reset(__json);
	}

	/////////////////////////////////////////////////////////////////////////////////////
	//
	// JSON::JSON(JSONType type)
	//
	// creates an empty JSON of type "type", only used to propagate error
	//
	JSON::JSON(JSONType type):JSON()
	{
		switch (type) {
		case JSONType::JSON_OBJECT: reset(static_cast<json_t*>(json_object())); break;
		case JSONType::JSON_ARRAY:	reset(static_cast<json_t*>(json_array()))  ; break;
		case JSONType::JSON_STRING:	reset(json_string( "" ));break;
		case JSONType::JSON_INTEGER:reset(json_integer( 0 ));break;
		case JSONType::JSON_NULL:   reset(static_cast<json_t*>(json_null()));break;
		case JSONType::JSON_FAULT:  type_= type;setFailBit();break;
		default: break;
		}
	}

	JSON::JSON()
	:fault_(nullptr),
	 type_(JSONType::JSON_NULL),
	 json_(json_null()),
	 parent_(NULL),
	 id(),
	 childList_(),
	 errorStr_(""),
	 warningStr_(""),
	 stringified_(""),
	 state_(goodbit),
	 jsonPtrIsBorrowed_(false)
	{	}

	JSON::JSON(JSON&& J)
	:fault_(J.fault_),
	 type_(J.type_),
	 json_(J.json_),
	 parent_(NULL),
	 id(J.id),
	 childList_(),
	 errorStr_(J.errorStr_),
	 warningStr_(""),
	 stringified_(""),
	 state_(J.state_),
	 jsonPtrIsBorrowed_(false)
	{
		// if the object owns the json, then take the ownership
		// if the object borrows the json, then shared the ownership
		if (!J.jsonPtrIsBorrowed_) J.json_=NULL;
		else json_incref(json_);
	}
	JSON::JSON(const string& s):JSON{s.c_str()}
	{}
	JSON::~JSON()
	{
		if (!jsonPtrIsBorrowed() && json_!= NULL)
		{
			json_decref(json_);
		}
		delete fault_;
	}

	JSON& JSON::fault()
	{
		if (fault_ == nullptr) fault_ = new JSON(JSONType::JSON_FAULT);
		return *fault_;
	}
	JSON& JSON::newElement(const std::string& key)
	{
		return operator[](key);
	}
	JSON& JSON::newElement()
	{
		return operator[](size());
	}
	int JSON::erase(const std::string& key) {
		if (!exist(key) || type() != JSONType::JSON_OBJECT)
			return 0;
		JSON& x = operator[](key); // get the element
		if (x.jsonPtrIsBorrowed()) json_object_del(json_, key.c_str());
		childList_.remove_if([&key](JSON& x){ return key == x.id.key; });
		return 1;
	}
	int	JSON::erase(size_t i) {
		if (!exist(i) || type() != JSONType::JSON_ARRAY) {
			return 0;
		}

		JSON& x = operator[](i); // get the element
		if (x.jsonPtrIsBorrowed()) {
			json_array_remove(json_, i);
		} else {syslog(LOG_INFO, "not removed");}
		childList_.remove_if([i](JSON& x){ return x.id.index == i; });
		return 1;
	}
	JSON& JSON::operator[](const std::string& key)
	{
		if (type() != JSONType::JSON_OBJECT) {
			if (type() == JSONType::JSON_FAULT) {
				return *this;
			}
			else if (type() ==  JSONType::JSON_NULL) {
				reset(json_object(  ));
				updateParent();
			}
			else {
				setFailBit(std::string("Attempt to access \"") + key + "\" of non-JSON_OBJECT");
				return fault();
			}
		}
		for (JSON& J : childList()) if (J.id.key == key) return J;
		return wrapper(key);
	}
	JSON& JSON::operator[](size_t index)
	{
		std::stringstream ss;
		if (type() != JSONType::JSON_ARRAY) {
			if (type() == JSONType::JSON_FAULT) return *this;
			ss << "Attempt to access [" << index << "] of non-JSON_ARRAY";
			setFailBit(ss.str());
			return fault();
		}
		for (JSON& J : childList()) if (J.id.index == index) return J;

		return wrapper(index);
	}

	void  JSON::operator=(const char* str) {
		if (type() == JSONType::JSON_FAULT) return;
		if (type() != JSONType::JSON_STRING) {
			reset(json_string( str ));
			updateParent();
		} else json_string_set(json_, str);
		return;
	}

	void  JSON::operator=(const std::string& str)
	{
		operator=(str.c_str());
	}

	void JSON::operator=(std::string&& str)
	{
		operator=(str.c_str());
	}

	size_t JSON::size()
	{
		if (type() ==  JSONType::JSON_ARRAY) return json_array_size(json_);
		if (type() ==  JSONType::JSON_OBJECT) return json_object_size(json_);
		return 0;
	}

	void JSON::operator=(JsonInt val)
	{
		if (type() == JSONType::JSON_FAULT) return;
		if (type() != JSONType::JSON_INTEGER)
		{
			reset(json_integer( static_cast<json_int_t>(val)));
			updateParent();
		} else json_integer_set(json_, static_cast<json_int_t>(val));

		return;
	}
	void JSON::operator=(unsigned val)
	{
		operator=(static_cast<JsonInt>(val));
	}
	void JSON::operator=(int val)
	{
		operator=(static_cast<JsonInt>(val));
	}
	void JSON::operator=(const JSON& J)
	{
		//if (type() == JSONType::JSON_FAULT || J.type() == JSONType::JSON_FAULT) return;
		json_error_t error;
		json_t * __json =json_deep_copy(J.json_); // make a fresh copy of json
		if (__json)
		{
			reset(__json);
			updateParent();
		}
		else { setFailBit(std::string(const_cast<char*>(error.text))); type_ = JSONType::JSON_FAULT;}
		return;
	}

	void JSON::operator=(JSON&& J) noexcept
	{
		//if (type() == JSONType::JSON_FAULT || J.type() == JSONType::JSON_FAULT) return;
		//if (type() == JSONType::JSON_FAULT || J.type() == JSONType::JSON_FAULT) return;
		reset(J.json_);
		J.json_=NULL;
		updateParent();

		return;
	}

	void JSON::operator=(bool boolean) {
		if (type() == JSONType::JSON_FAULT) return;
		boolean ?  reset(json_true()) : reset(json_false());
		updateParent();
		return;
	}
	bool JSON::exist(const string& k) const {
		if (type() == JSONType::JSON_OBJECT) {
			return (json_object_get(json_, k.c_str()) != NULL);
		}
		return false;
	}

	bool JSON::exist(size_t i) const {
		if (type() == JSONType::JSON_ARRAY) {
			return (json_array_get(json_, i) != NULL);
		}
		return false;
	}

	void JSON::forEachInObj(std::function<void(const char* key,JSON&)> f){
		if (type() != JSONType::JSON_OBJECT) return;
		for (void *iter = json_object_iter(json_); iter; iter = json_object_iter_next(json_, iter)) {
			const char* key = json_object_iter_key(iter);
			f(key, operator[](key));
		}
	}
	void JSON::forEachInArr(std::function<void(unsigned,JSON&)> f) {
		if (type() != JSONType::JSON_ARRAY) return;
		for(size_t index_ = 0; index_ < size(); index_++)
			f(index_, operator[](index_));
	}
	void JSON::updateParent() {
		if (parent_ != NULL) {
			jsonPtrIsBorrowed_=true;
			if (parent_->type() == JSONType::JSON_OBJECT) json_object_set_new(parent_->json_, id.key.c_str(), json_);
			else if (parent_->type() == JSONType::JSON_ARRAY) json_array_set_new(parent_->json_, id.index, json_);
			else setFailBit("Invalid type of parent");
		}
	}
	JsonList& JSON::childList() {return childList_;}
	JsonString JSON::stringify() const {
		JsonString tempStr("");
		char *temp = json_dumps(json_,JSON_ENSURE_ASCII|JSON_COMPACT|JSON_INDENT(0));
		if (temp)
		{
			tempStr = temp;
			free(temp);
		}
		return tempStr;
	}

	JsonString JSON::toString() {
		JsonString tempStr("");
		if (type() != JSONType::JSON_STRING) {/* report error */ tempStr= "";}
		else tempStr = json_string_value(json_);
		return tempStr;
	}
	bool JSON::toBool()
	{
		return type() == JSONType::JSON_TRUE;
	}
	JsonInt JSON::toInteger() {
		JsonInt rtn = 0;
		switch (type())
		{
		case JSONType::JSON_INTEGER:
			rtn = static_cast<JsonInt>(json_integer_value(json_)); break;
		case JSONType::JSON_STRING:
			if (1) {
				std::string temp="";
				size_t a = strlen(json_string_value(json_));
				if (a & static_cast<size_t>(1) == 1) { temp += "0"; a++;}
				temp += json_string_value(json_);
//				kStrToInt((void*)&rtn, temp.c_str(), std::min(a>>1, sizeof(JsonInt)));
                rtn = stoi(temp, 0, 16);
			}
			break;
		default:setFailBit("Invalid conversion to integer");break;
		}
		return rtn;
	}
	void JSON::toFile(const char* path){json_dump_file(json_,path, JSON_INDENT(0)|JSON_COMPACT);}
	JSONType  JSON::type() const { return type_; }
	JsonState JSON::state() { return state_; }
	JsonState JSON::stateAll() {
		JsonState x = state();
		for (JsonList::iterator it = childList().begin(); it != childList().end(); ++it)
			x |= (*it).stateAll();
		return x;
	}
	void JSON::setFailBit() { state_ |= failbit;}
	void JSON::setFailBit(std::string message) {setFailBit(); errorStr_ += message; errorStr_ += "; "; }
	void JSON::setFailBit(std::stringstream message) {setFailBit(message.str());}

	bool JSON::jsonPtrIsBorrowed()
	{
		return jsonPtrIsBorrowed_;
	}
	void JSON::reset(json_t* j)
	{
		if (json_) json_decref(json_);
		json_ = j;
		type_ = static_cast<JSONType>json_typeof(json_);
		childList().clear();
	}
	bool JSON::fail() { return ( state() & failbit );}
	bool JSON::good() { return ( state() == goodbit );}
	const JsonString& JSON::errorStr() {return errorStr_;}
	JsonString JSON::errorStrAll(){
		JsonString x = errorStr();
		for (JsonList::iterator it = childList().begin(); it != childList().end(); ++it) x += (*it).errorStrAll();
		return x;
	}

	JSON& JSON::wrapper(const std::string& key)
	{
		JSON& x = *(childList().emplace(childList().end()));
		x.parent_ = this;
		x.id.key = key;

		if (json_t * json = json_object_get(json_, key.c_str()))
		{
			x.reset(json);
		} else
		{
			x.updateParent();
		}
		x.jsonPtrIsBorrowed_ = true;

		return x;
	}
	JSON& JSON::wrapper(size_t index)
	{
		JSON& x = *(childList().emplace(childList().end()));
		x.parent_ = this;
		x.id.index = index;
		for (size_t i = size(); i <= index; i++)
		{
			json_array_append_new(json_, static_cast<json_t*>(json_null()));
		}

		if (json_t * json = json_array_get(json_, index))
		{
			x.reset(json);
		} else
		{
			x.updateParent();
		}
		x.jsonPtrIsBorrowed_ = true;

		return x;
	}
} 