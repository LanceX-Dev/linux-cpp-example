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

#ifndef ROUTER_H
#define ROUTER_H
#include <string>
#include <memory>
#include <map>
#include <typeindex>
#include <list>
#include "jansson.h"

namespace lancex 
{
    // This si the default path store all user specific files
    const char USER_FILE_PATH[] = "~/.lancex-userfile";
    const char CREDENTIAL_FILE[] = "device.json";
    const char CERT_FILE[] = "cert.pem"; 
    const char USOCKETPATH[] = "/tmp/lancex-usock";
    const char QUERY_URL[] = "https://account.lancex.cc/device/info";
        
    void init();
    
    std::string localRpcRequest(const std::string& in);
    using namespace std;
	template<class F>
	struct function_traits;

	// function pointer
	template<class R, class... Args>
	struct function_traits<R(*)(Args...)> : public function_traits<R(Args...)>
	{};

	template<class R, class... Args>
	struct function_traits<R(Args...)>
	{
		using return_type = R;
		static constexpr std::size_t arity = sizeof...(Args);
		using wrapper = std::function<void(Args...)>;
		template <std::size_t N>
		struct argument
		{
			static_assert(N < arity, "error: invalid parameter index.");
			using type = typename std::tuple_element<N,std::tuple<Args...>>::type;
		};
	};
    
	// member function pointer
	template<class C, class R, class... Args>
	struct function_traits<R(C::*)(Args...)> : public function_traits<R(Args...)>
	{};

	// const member function pointer
	template<class C, class R, class... Args>
	struct function_traits<R(C::*)(Args...) const> : public function_traits<R(Args...)>
	{};

	template<class F>
	struct function_traits
	{
	private:
		using call_type = function_traits<decltype(&F::operator())>;
	public:
		using return_type = typename call_type::return_type;
		static constexpr std::size_t arity = call_type::arity;
		using wrapper = typename call_type::wrapper;
		template <std::size_t N>
		struct argument
		{
			static_assert(N < arity, "error: invalid parameter index.");
			using type = typename call_type::template argument<N>::type;
		};
	};

	template<class F>
	struct function_traits<F&> : public function_traits<F> {};

	template<class F>
	struct function_traits<F&&> : public function_traits<F> {};

	struct __Function {	};

	template <typename T>
	struct BasicFunction : __Function
	{
		using wrapper = typename function_traits<T>::wrapper;
		wrapper function;
		BasicFunction(wrapper function) : function(function) { }
	};

	typedef map< type_index, unique_ptr<__Function>> Handlers;

	Handlers& __container(const string& e, const string& u);
	//}
	template <typename F>
	static void handler(const string& event, const string& uri, F function)
	{
		using wrapper = typename function_traits<F>::wrapper;
		Handlers& H = __container(event,uri);
		type_index index(typeid(wrapper));
		unique_ptr<__Function> func_ptr(new BasicFunction<F>(wrapper(function)));
		H[index] = std::move(func_ptr);
	}

	template <typename... Args>
	static void trigger(const string& event, const string& uri, Args&&... args)
	{
		const Handlers& H = __container(event,uri);
		using wrapper = typename function_traits<void(Args...)>::wrapper;
		std::type_index index(typeid(wrapper));

		Handlers::const_iterator i = H.lower_bound(index);
		Handlers::const_iterator j = H.upper_bound(index);
		for (;i!=j; ++i)
		{
			const __Function &f = *i->second;
			wrapper func =  static_cast<const BasicFunction<void(Args...)> &>(f).function;
			func(std::forward<Args>(args)...);
		}
	}

	template <typename F>
	void simpleHandler(const string& uri, F function)
	{
		using wrapper = typename function_traits<F>::wrapper;
		Handlers& H = __container("_",uri);
		type_index index(typeid(wrapper));
		unique_ptr<__Function> func_ptr(new BasicFunction<F>(wrapper(function)));
		H[index] = move(func_ptr);
	}
    
	template <typename... Args>
	void simpleTrigger(const string& uri, Args&&... args)
	{
		const Handlers& H = __container("_",uri);
		using wrapper = typename function_traits<void(Args...)>::wrapper;
		type_index index(typeid(wrapper));

		Handlers::const_iterator i = H.lower_bound(index);
		Handlers::const_iterator j = H.upper_bound(index);
		for (;i!=j; ++i)
		{
			const __Function &f = *i->second;
			wrapper func =  static_cast<const BasicFunction<void(Args...)> &>(f).function;
			func(forward<Args>(args)...);
		}
	}
    
    template <typename F>
	static void httpHandler(const string& uri, F function)
	{
		using wrapper = typename function_traits<F>::wrapper;
		Handlers& H = __container("Application",uri);
		type_index index(typeid(wrapper));
		unique_ptr<__Function> func_ptr(new BasicFunction<F>(wrapper(function)));
		H[index] = std::move(func_ptr);
	}
}


namespace lancex {
    
    //helper functions
    
    int NanoSleep(struct timespec *interval);
    int Sleep(size_t interval);

	typedef long long int JsonInt;
	typedef long long unsigned JsonUInt;
	typedef std::string JsonString;
	typedef uint16_t JsonState;
	enum class JSONType
	{
		JSON_OBJECT = JSON_OBJECT,
		JSON_ARRAY  = JSON_ARRAY,
		JSON_STRING = JSON_STRING,
		JSON_INTEGER = JSON_INTEGER,
		JSON_REAL = JSON_REAL,
		JSON_TRUE = JSON_TRUE,
		JSON_FALSE = JSON_FALSE,
		JSON_NULL = JSON_NULL,
		JSON_EMPTY,
		JSON_FAULT
	};
	using JsonType = JSONType ;
	enum class JsonSourceType {FILE, STRING};
	class JSON;

	static const JsonState failbit = 0x0001;
	static const JsonState badbit  = 0x0002;
	static const JsonState warnbit = 0x0004;
	static const JsonState goodbit = 0x0000;

	typedef std::list<JSON> JsonList;

	class JSON
	{
	protected:
		bool jsonPtrIsBorrowed();
		bool jsonPtrIsBorrowed_;
		void reset(json_t* j);

		struct { std::string key; size_t index; } id;
	private:
		json_t* json_;
		JSON* parent_;
		JSON* fault_;
		JSONType type_;
		JsonList childList_;
		JsonString errorStr_;
		JsonString warningStr_;
		JsonString stringified_;
		JsonState state_;

		JSON& fault();
		void updateParent();
		JSON& wrapper(const std::string&);
		JSON& wrapper(size_t);
	public:

		JSON();
		JSON(JSONType);
		JSON(const char* source, JsonSourceType type);
		JSON(const char* source);
		JSON(const JSON& J);
		JSON(JSON&& J);
		JSON(const std::string& s);
		~JSON();
		JSONType type() const;
		JSON& newElement(const std::string& key);
		JSON& newElement();
		int erase(const std::string& key);
		int	erase(size_t i);
		JSON& operator[](const std::string& key);
		JSON& operator[](size_t index);
		size_t size();
		void operator=(const std::string& str);
		void operator=(std::string&& str);
		void operator=(const char* str);
		void operator=(JsonInt val);
		void operator=(unsigned val);
		void operator=(int val);
		void operator=(const JSON& J);
		void operator=(JSON&& J) noexcept;
		void operator=(bool boolean);
		bool exist(const std::string&) const;
		bool exist(size_t) const;
		void forEachInObj(std::function<void(const char*,JSON&)> f);
		void forEachInArr(std::function<void(unsigned,JSON&)> f);
		JsonInt toInteger();
		JsonString toString();
		bool toBool();
		JsonString stringify() const;
		JsonList& childList();
		void toFile(const char* path);
		JsonState state();
		JsonState stateAll();
		void setFailBit();
		void setFailBit(std::string);
		void setFailBit(std::stringstream);
		const JsonString& errorStr();
		JsonString errorStrAll();
		bool fail();
		bool good();
	};
} 
namespace lancex {
    // REST stuff    
    using namespace std;
	const char EventTag[] = "Application";
	class __Context
	{
	public:
		__Context(string uri);
		~__Context();
		string& URI();
		string& parameter();
		string& response();
		string& request();
		void parameter(string P);
		void response(string&& R);
		void response(const string& R);
		void request(const string& S);
	private:
		string uri_;
		string parameter_;
		string response_;
		string request_;
	};
	typedef __Context& Context;

	Context getContext(const std::string& uri);
    void handleRESTful(const string& req, std::string& rsp);
    
    namespace protocol {
        namespace ver2 {
            using namespace std;
            const char VER[] = "ver";
            const char URI[] = "uri";
            const char ARG[] = "arg";
            namespace uri_labels
            {
                const char pingreq[] = "ping/req";
                const char pingrsp[] = "ping/rsp";
                const char msgInd[] = "msg/ind";
                const char msgReq[] = "msg/req";
                const char wantrsp[] = "rsp";
                const char token[] = "tkn";
                const char SEQ[] = "seq";
                const char STAT[] = "sta";
            }
            inline lancex::JSON req_struct(const string& uri)
            {
                JSON x{JSONType::JSON_OBJECT};
                x["ver"] = 2;
                x["uri"] = uri;
                x["tod"] = (int)time(NULL);
                return x;
    		}
    		inline lancex::JSON req_struct(const string& uri, string&& pl)
    		{
    			JSON x = req_struct(uri);
    			x[ARG] = pl;
    			return x;
    		}
    		inline lancex::JSON req_struct(const string& uri, const string& pl)
    		{
    			JSON x = req_struct(uri);
    			x[ARG] = pl;
    			return x;
    		}
        }
    }
}

#define LOG_ERROR_MESSAGE(...) 
#define LOG_MESSAGE(...) 
#define MAX_SOCKET_BUFFER 262144
#endif