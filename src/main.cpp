#include <iostream>
#include <error.h>
#include <err.h>
#include <errno.h>
#include <assert.h>
#include <execinfo.h>
#include <unistd.h>
#include <string>
#include <cstring>
#include <chrono>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <future>
#include <functional>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <atomic>
#include <vector>
#include <math.h>
#include <algorithm> // std::all_of
#include <inttypes.h> // todo: proper printf macros
#include <unordered_map>
#include <linux/nbd.h>
#include <curl/curl.h>

using namespace std;
enum
{
	SECTOR_SIZE = 4096, BLOCK_SIZE = 4096, CAC_CODE_SIZE = 25
};
string argv_username;
string argv_password;
string sectorindex_file;
string nbd_path;
uint64_t sectors = 0;
uint number_of_worker_threads = 0;
atomic_uint number_of_worker_threads_ready(0);
atomic_bool nbd_initialization_started(false);
atomic_bool nbd_initialization_success(false);
mutex sector_readwrite_mutex;
/*
 struct io_cache_object
 {
 time_t mtime;
 std::string data;
 //uint64_t sector; is the io_cache key.
 };*/
// could also be called the upload queue.
std::unordered_map<uint64_t, std::string> io_cache;/* =
 {
 { SECTOR_SIZE*0, io_cache_object
 { .mtime = 0, .data = string(SECTOR_SIZE, 'A') } },
 { SECTOR_SIZE*1, io_cache_object
 { .mtime = 0, .data = string(SECTOR_SIZE, 'B') } } };
 */
shared_mutex io_cache_mutex;

struct
{
	int nbd_fd;
	int localrequestsocket;
	int remoterequestsocket;
}volatile kernelIPC =
{ .nbd_fd = -1, .localrequestsocket = -1, .remoterequestsocket = -1 };
FILE *close_me_on_cleanup = NULL;
// <headache>
void* nbd_doit_thread(void *return_before_doingit_promise);
void install_shutdown_signal_handlers(void);
void exit_global_cleanup(void);
void nbdreply(const int fd, const void *buf1, const size_t buf1_size,
		const void *buf2, const size_t buf2_size);
void cac_delete_eventually(const string& id);
//</headache>
#if !defined(likely)
#if defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__) || (defined(__IBMC__) || defined(__IBMCPP__))
#if defined(__cplusplus)
// https://stackoverflow.com/a/43870188/1067003
#define likely(x)       __builtin_expect(static_cast<bool>((x)),1)
#define unlikely(x)     __builtin_expect(static_cast<bool>((x)),0)
#else
#define likely(x)       __builtin_expect(!!(x),1)
#define unlikely(x)     __builtin_expect(!!(x),0)
#endif
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif
#endif

#if !defined(UNREACHABLE)
//TODO: check MSVC/ICC
#if defined(__GNUC__) || defined(__clang__)
#define UNREACHABLE() (__builtin_unreachable())
#else
//not sure what to do here...
#define UNREACHABLE() ()
#endif
#endif

#if !defined(NTOHL)
#if !defined(__BYTE_ORDER)
#error Failed to detect byte order! fix the code yourself and/or submit a bugreport!
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
/* The host byte order is the same as network byte order,
 so these functions are all just identity.  */
#define NTOHL(x)	((uint32_t)x)
#define NTOHS(x)	((uint16_t)x)
#define HTONL(x)	((uint32_t)x)
#define HTONS(x)	((uint16_t)x)
#define HTONLL(x)	((uint64_t)x)
#define NTOHLL(x)	((uint64_t)x)
#else
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define NTOHL(x)	__bswap_constant_32 ((uint32_t)x)
#define NTOHS(x)	__bswap_constant_16 ((uint16_t)x)
#define HTONL(x)	__bswap_constant_32 ((uint32_t)x)
#define HTONS(x)	__bswap_constant_16 ((uint16_t)x)
#define HTONLL(x)	__bswap_constant_64 ((uint64_t)x)
#define NTOHLL(x)	__bswap_constant_64 ((uint64_t)x)
#else
#error Failed to detect byte order! fix the code yourself and/or submit a bugreport!
#endif
# endif
#endif

#define macrobacktrace() { \
void *array[20]; \
int traces=backtrace(array,sizeof(array)/sizeof(array[0])); \
if(traces<=0) { \
	fprintf(stderr,"failed to get a backtrace!"); \
} else { \
backtrace_symbols_fd(array,traces,STDERR_FILENO); \
} \
}

#define myerror(status,errnum,...){macrobacktrace();error_at_line(status,errnum,__FILE__,__LINE__,__VA_ARGS__);}
// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2012/n3451.pdf
// jesus christ devs, just give us a .ignore() already.
template<typename T>
void noget(T&& in)
{
	// uncomment line below to effectively make all noget()'s synchronous
	//in.get();return;
	static std::mutex vmut;
	static std::vector<T> vec;
	static std::thread getter;
	static std::mutex single_getter;
	if (unlikely(single_getter.try_lock()))
	{
		getter = std::thread([&]()->void
		{
			size_t size;
			for(;;)
			{
				do
				{
					vmut.lock();
					size=vec.size();
					if(size>0)
					{
						T target=std::move(vec[size-1]);
						vec.pop_back();
						vmut.unlock();
						// cerr << "getting!" << endl;
				target.get();
			}
			else
			{
				vmut.unlock();
			}
		}while(size>0);
		// ¯\_(ツ)_/¯
		this_thread::sleep_for(std::chrono::seconds(1));
	}
});
		getter.detach();
	}
	vmut.lock();
	vec.push_back(std::move(in));
	vmut.unlock();
}
uint64_t nigghash(char * buf, size_t len)
{
	uint64_t ret = 0;
	uint64_t curr;
	while (len > 0)
	{
		if (len >= 8)
		{
			len -= 8;
			curr = *(uint64_t*) &buf[len];
		}
		else if (len >= 4)
		{
			len -= 4;
			curr = *(uint32_t*) &buf[len];
		}
		else if (len >= 2)
		{
			len -= 2;
			curr = *(uint16_t*) &buf[len];
		}
		else
		{
			--len;
			curr = *(uint8_t*) &buf[len];
		}
		ret += curr;
	}
	return ret;
}
void *emalloc(const size_t size)
{
	void *ret = malloc(size);
	if (unlikely(size && !ret))
	{
		myerror(EXIT_FAILURE, errno,
				"malloc failed to allocate %zu bytes. terminating...\n", size);
	}
	return ret;
}
void *erealloc(void *ptr, const size_t size)
{
	void *ret = realloc(ptr, size);
	if (unlikely(size && !ret))
	{
		myerror(EXIT_FAILURE, errno, "realloc failed to allocate %zu bytes.",
				size);
	}
	return ret;
}
void *ecalloc(const size_t num, const size_t size)
{
	void *ret = calloc(num, size);
	if (unlikely(num > 0 && size > 0 && !ret))
	{
		myerror(EXIT_FAILURE, errno, "calloc failed to allocate %zu*%zu bytes.",
				num, size);
	}
	return ret;
}
int efseek(FILE *stream, const long int offset, const int origin)
{
	const int ret = fseek(stream, offset, origin);
	if (unlikely(ret != 0))
	{
		myerror(EXIT_FAILURE, errno, "fseek() failed to seek to %lu", offset);
	}
	return ret;
}
size_t efwrite(const void * ptr, const size_t size, const size_t count,
		FILE * stream)
{
	const size_t ret = fwrite(ptr, size, count, stream);
	if (unlikely(size > 0 && count > 0 && ret != count))
	{
		myerror(EXIT_FAILURE, ferror(stream),
				"fwrite() failed to write %lu bytes! errno: %i ferror: %i",
				(size * count), errno, ferror(stream));
	}
	return ret;
}
//this  almost has to be a macro because of how curl_easy_setopt is made (a macro taking different kinds of parameter types)
#define ecurl_easy_setopt(handle, option, parameter)({ \
CURLcode ret_8uyr7t6sdygfhd=curl_easy_setopt(handle,option,parameter); \
if(unlikely( ret_8uyr7t6sdygfhd  != CURLE_OK)){ \
	 myerror(EXIT_FAILURE,errno,"curl_easy_setopt failed to set option %i. CURLcode: %i curl_easy_strerror: %s\n", option, ret_8uyr7t6sdygfhd, curl_easy_strerror(ret_8uyr7t6sdygfhd));   \
	} \
});
#define ecurl_multi_setopt(multi_handle,option, parameter)({ \
		CURLMcode ret_7yruhj=curl_multi_setopt(multi_handle,option,parameter);\
		if(unlikely(ret_7yruhj!= CURLM_OK)){ \
			myerror(EXIT_FAILURE,errno,"curl_multi_setopt failed to set option %i CURLMcode: %i curl_multi_strerror: %s\n",option,ret_7yruhj,curl_multi_strerror(ret_7yruhj));\
		} \
});

#define ecurl_multi_add_handle(multi_handle, easy_handle)({ \
	CURLMcode ret_8ujih=curl_multi_add_handle(multi_handle,easy_handle);\
	if(unlikely(ret_8ujih!=CURLM_OK)){ \
		myerror(EXIT_FAILURE,errno,"curl_multi_add_handle failed. CURLMcode: %i curl_multi_strerror: %s\n",ret_8ujih,curl_multi_strerror(ret_8ujih)); \
	}\
});
#define ecurl_easy_getinfo(curl,info,...){ \
	CURLcode ret=curl_easy_getinfo(curl,info,__VA_ARGS__); \
	if(unlikely(ret!=CURLE_OK)){ \
		 myerror(EXIT_FAILURE,errno,"curl_easy_getinfo failed to get info %i. CURLCode: %i curl_easy_strerror: %s\n", info, ret, curl_easy_strerror(ret));   \
	} \
}

std::string curlprettyerror(const string name, const CURLcode errnum)
{
	return string(
			name + " error " + to_string(errnum) + ": "
					+ string(curl_easy_strerror(errnum)));
}
CURL* ecurl_easy_init()
{
	CURL *ret = curl_easy_init();
	if (unlikely(ret==NULL))
	{
		myerror(EXIT_FAILURE, errno,
				"curl_easy_init() failed! (why? i have no idea.)");
	}
	return ret;
}
CURLM* ecurl_multi_init()
{
	CURLM *ret = curl_multi_init();
	if (unlikely(ret==NULL))
	{
		myerror(EXIT_FAILURE, errno, "curl_multi_init() failed!");
	}
	return ret;
}
curl_mime* ecurl_mime_init(CURL *easy_handle)
{
	curl_mime *ret = curl_mime_init(easy_handle);
	if (unlikely(ret==NULL))
	{
		myerror(EXIT_FAILURE, errno, "curl_mime_init() failed!");
	}
	return ret;
}
curl_mimepart* ecurl_mime_addpart(curl_mime *mime)
{
	curl_mimepart *ret = curl_mime_addpart(mime);
	if (unlikely(ret==NULL))
	{
		myerror(EXIT_FAILURE, errno, "curl_mime_addpart() failed!");
	}
	return ret;

}
struct curl_slist* ecurl_slist_append(struct curl_slist * list,
		const char * c_string)
{
	struct curl_slist *ret = curl_slist_append(list, c_string);
	if (unlikely(ret==NULL))
	{
		myerror(EXIT_FAILURE, errno, "curl_slist_append() failed!");
	}
	return ret;
}
CURLcode ecurl_mime_data(curl_mimepart * part, const char * data,
		size_t datasize)
{
	CURLcode ret = curl_mime_data(part, data, datasize);
	if (unlikely(ret != CURLE_OK))
	{
		throw runtime_error(curlprettyerror("ecurl_mime_data() failed!", ret));
	}
	return ret;
}
CURLcode ecurl_mime_name(curl_mimepart * part, const char * name)
{
	CURLcode ret = curl_mime_name(part, name);
	if (unlikely(ret != CURLE_OK))
	{
		throw runtime_error(curlprettyerror("curl_mime_name() failed!", ret));
	}
	return ret;
}
CURLcode ecurl_mime_filename(curl_mimepart * part, const char * filename)
{
	CURLcode ret = curl_mime_filename(part, filename);
	if (unlikely(ret != CURLE_OK))
	{
		throw runtime_error(
				curlprettyerror("curl_mime_filename() failed!", ret));
	}
	return ret;

}
CURLcode ecurl_easy_perform(CURL *easy_handle)
{
	CURLcode ret = curl_easy_perform(easy_handle);
	if (unlikely(ret != CURLE_OK))
	{
		throw runtime_error(curlprettyerror("curl_easy_perform()", ret));
	}
	return ret;
}

CURLMcode ecurl_multi_perform(CURLM *multi_handle, int *running_handles)
{
	CURLMcode ret = curl_multi_perform(multi_handle, running_handles);
	if (unlikely(ret != CURLM_OK))
	{
		myerror(EXIT_FAILURE, errno,
				"curl_multi_perform failed. CURLMcode: %i curl_multi_strerror: %s\n",
				ret, curl_multi_strerror(ret));
	}
	return ret;
}
CURLMcode ecurl_multi_wait(CURLM *multi_handle, struct curl_waitfd extra_fds[],
		unsigned int extra_nfds, int timeout_ms, int *numfds)
{

	CURLMcode ret = curl_multi_wait(multi_handle, extra_fds, extra_nfds,
			timeout_ms, numfds);
	if (unlikely(ret != CURLM_OK))
	{
		myerror(EXIT_FAILURE, errno,
				"curl_multi_wait failed. CURLMcode: %i curl_multi_strerror: %s\n",
				ret, curl_multi_strerror(ret));
	}
	return ret;
}
CURLMcode ecurl_multi_cleanup(CURLM *multi_handle)
{
	CURLMcode ret = curl_multi_cleanup(multi_handle);
	if (unlikely(ret != CURLM_OK))
	{
		myerror(EXIT_FAILURE, errno,
				"curl_multi_cleanup failed. CURLMcode: %i curl_multi_strerror: %s\n",
				ret, curl_multi_strerror(ret));

	}
	return ret;
}
CURL *ecurl_easy_duphandle(CURL *handle)
{
	errno = 0;
	cout << "dup!" << endl;
	CURL *ret = curl_easy_duphandle(handle);

	if (unlikely(ret==NULL))
	{
		myerror(EXIT_FAILURE, errno, "curl_easy_duphandle() failed! ");
	}
	return ret;
}
CURL *ecurl_easy_duphandle_with_cookies(CURL *easy_handle)
{
	CURL *ret = ecurl_easy_duphandle(easy_handle);
	struct curl_slist *cookies = NULL;
	CURLcode res = curl_easy_getinfo(easy_handle, CURLINFO_COOKIELIST,
			&cookies);
	if (res == CURLE_OK && cookies)
	{
		struct curl_slist *each = cookies;
		while (each)
		{
			ecurl_easy_setopt(ret, CURLOPT_COOKIELIST, each->data);
			each = each->next;
		}
		curl_slist_free_all(cookies);
	}
	return ret;
}
void ecurl_clone_cookies(CURL *source_handle, CURL *target_handle)
{
	struct curl_slist *cookies = NULL;
	CURLcode res = curl_easy_getinfo(source_handle, CURLINFO_COOKIELIST,
			&cookies);
	if (res == CURLE_OK && cookies)
	{
		struct curl_slist *each = cookies;
		while (each)
		{
			ecurl_easy_setopt(target_handle, CURLOPT_COOKIELIST, each->data);
			each = each->next;
		}
		curl_slist_free_all(cookies);
	}

}
char *ecurl_easy_escape(CURL * curl, const char * instring, const int length)
{
	char *ret = curl_easy_escape(curl, instring, length);
	if (unlikely(ret==NULL))
	{
		throw runtime_error(
				string(
						"curl_easy_escape() failed! why? dunno, out of ram? input string: ")
						+ instring);
	}
	return ret;
}
string urlencode(const string& str)
{
	char *escaped = curl_escape(str.c_str(), str.length());
	if (unlikely(escaped==NULL))
	{
		throw runtime_error("curl_escape failed!");
	}
	string ret = escaped;
	curl_free(escaped);
	return ret;
}
// here is how zswap does it: https://github.com/torvalds/linux/blob/master/mm/zswap.c#L971 / zswap_is_page_same_filled
// https://stackoverflow.com/a/46963010/1067003
bool memory_is_all_zeroes(unsigned char const* const begin,
		std::size_t const bytes)
{
	return std::all_of(begin, begin + bytes, [](unsigned char const byte)
	{	return byte == 0;});
}
bool memory_is_all_zeroes(char const* const begin, std::size_t const bytes)
{
	return memory_is_all_zeroes(
			reinterpret_cast<unsigned char const* const >(begin), bytes);
}
void sector_copy(const string& src, char *target)
{
	assert(src.length() == 0 || src.length() == SECTOR_SIZE);
	if (src.length() == 0)
	{
		memset(target, 0, SECTOR_SIZE);
	}
	else
	{
		memcpy(target, &src[0], SECTOR_SIZE);
	}
}
std::string string_to_hex(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

class Downloadcacapi
{
public:
	string download(const string& id);
	vector<string> download_multi(const vector<string> codes);
	string upload(const string& data, const string& savename);
	struct Upload_multi_arg
	{
		string data;
		string savename;
	};
	vector<string> upload_multi(
			const vector<Downloadcacapi::Upload_multi_arg> args);
	void delete_upload(const string& id);
	future<bool> async_delete_upload(const string& id);
	Downloadcacapi(const string& username, const string& password);
	~Downloadcacapi();
	vector<string> get_cookies();
private:
//	time_t last_cookie_refresh_time; // todo..
	//todo: refreshcookiesession()
	const string username;
	const string password;
	string curl_exec(const string& url);
	void curl_exec_faster1(const string& url);
	CURL *ch;
	string responsebuf;
	void login();
	void logout();
	std::thread cookie_session_keepalive_thread;
	CURL *cookie_session_keepalive_thread_curl;
	time_t last_interaction_time;
	static size_t curl_write_hook(const void * read_ptr, const size_t size,
			const size_t count, void *s_ptr);

};
// <headache2>
void cac_get_data(Downloadcacapi& cac, const uint64_t pos, const uint32_t len,
		char* buf, FILE *fp);
void cac_write_data(Downloadcacapi& cac, const uint64_t pos, const uint32_t len,
		const char *buf, FILE *fp);

vector<string> cac_get_sector_codes(size_t pos, const size_t length, FILE *fp);
void cac_update_sectorcode(FILE *fp, const uint64_t sectornum,
		const string& newcode);

//</headache2>
size_t Downloadcacapi::curl_write_hook(const void * read_ptr, const size_t size,
		const size_t count, void *s_ptr)
{
	(*(string*) s_ptr).append((const char*) read_ptr, size * count);
	return count;
}

string Downloadcacapi::download(const string& id)
{
	this->last_interaction_time = time(NULL);
	ecurl_easy_setopt(this->ch, CURLOPT_HTTPGET, 1);
	return (this->curl_exec(
			"https://download.cloudatcost.com/user/download.php?filecode="
					+ urlencode(id)));
}
vector<string> Downloadcacapi::download_multi(const vector<string> codes)
{

	const size_t num = codes.size();
	vector<string> ret;
	if (num < 1)
	{
		//wtf
		return ret;
	}
	else
	{
		this->last_interaction_time = time(NULL);
	}
	ret.resize(num);
	CURL *handles[num];
	CURLM *multi_handle = ecurl_multi_init();
	int still_running; /* keep number of running handles */
	for (size_t i = 0; i < num; ++i)
	{
		//handles[i] = ecurl_easy_duphandle_with_cookies(this->ch);
		handles[i] = ecurl_easy_init();
		ecurl_clone_cookies(this->ch, handles[i]);
		ecurl_easy_setopt(handles[i], CURLOPT_WRITEFUNCTION,
				Downloadcacapi::curl_write_hook);
		ecurl_easy_setopt(handles[i], CURLOPT_WRITEDATA, &(ret[i]));
		ecurl_easy_setopt(handles[i], CURLOPT_URL,
				string(
						"https://download.cloudatcost.com/user/download.php?filecode="
								+ urlencode(codes[i])).c_str());
		ecurl_multi_add_handle(multi_handle, handles[i]);
	}
	int repeats = 0;
	do
	{
		int numfds;
		ecurl_multi_perform(multi_handle, &still_running);
		/* wait for activity, timeout or "nothing" */
		ecurl_multi_wait(multi_handle, NULL, 0, 1000, &numfds);

		/* 'numfds' being zero means either a timeout or no file descriptors to
		 wait for. Try timeout on first occurrence, then assume no file
		 descriptors and no file descriptors to wait for means wait for 100
		 milliseconds. */
		if (!numfds)
		{
			repeats++; /* count number of repeated zero numfds */
			if (repeats > 1)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		}
		else
		{
			repeats = 0;
		}
	} while (still_running);
	{
		ecurl_multi_cleanup(multi_handle);
		for (size_t i = 0; i < num; ++i)
		{
			curl_easy_cleanup(handles[i]);
		}
	}
	return ret;
}
vector<string> Downloadcacapi::upload_multi(
		const vector<Downloadcacapi::Upload_multi_arg> args)
{
	const size_t num = args.size();
	vector<string> ret;
	if (num < 1)
	{
		//wtf
		return ret;
	}
	else
	{
		this->last_interaction_time = time(NULL);
	}

	ret.resize(num);
	CURL *handles[num] =
	{ NULL };
	curl_mime *mime1[num] =
	{ NULL };	// per-curl
	curl_mimepart *part1[num] =
	{ NULL }; //per-curl
	struct curl_slist *slist1 = NULL; // shared
	slist1 = ecurl_slist_append(slist1, "X-Requested-With: XMLHttpRequest");
	CURLM *multi_handle = ecurl_multi_init();
	int still_running; /* keep number of running handles */
	for (size_t i = 0; i < num; ++i)
	{
		//handles[i] = ecurl_easy_duphandle_with_cookies(this->ch);
		handles[i] = ecurl_easy_init();
		ecurl_clone_cookies(this->ch, handles[i]);
		mime1[i] = ecurl_mime_init(handles[i]);
		part1[i] = ecurl_mime_addpart(mime1[i]);
		ecurl_mime_data(part1[i], "", CURL_ZERO_TERMINATED);
		ecurl_mime_name(part1[i], "days");
		part1[i] = ecurl_mime_addpart(mime1[i]);
		ecurl_mime_data(part1[i], "", CURL_ZERO_TERMINATED);
		ecurl_mime_name(part1[i], "downloads");
		part1[i] = ecurl_mime_addpart(mime1[i]);
		ecurl_mime_data(part1[i], "", CURL_ZERO_TERMINATED);
		ecurl_mime_name(part1[i], "password");
		part1[i] = ecurl_mime_addpart(mime1[i]);
		//ecurl_mime_filedata(part1[i], "/dev/null");
		ecurl_mime_data(part1[i], &(args[i].data[0]), args[i].data.length());
		ecurl_mime_filename(part1[i], args[i].savename.c_str());
		ecurl_mime_name(part1[i], "file");
		ecurl_easy_setopt(handles[i], CURLOPT_MIMEPOST, mime1[i]);
		ecurl_easy_setopt(handles[i], CURLOPT_HTTPHEADER, slist1);
		//ecurl_easy_setopt(handles[i],CURLOPT_URL,"http://dumpinput.ratma.net");
		ecurl_easy_setopt(handles[i], CURLOPT_URL,
				"https://download.cloudatcost.com/upload.php");
		ecurl_easy_setopt(handles[i], CURLOPT_WRITEFUNCTION,
				Downloadcacapi::curl_write_hook);
		ecurl_easy_setopt(handles[i], CURLOPT_WRITEDATA, &(ret[i]));
		ecurl_multi_add_handle(multi_handle, handles[i]);
	}
	int repeats = 0;
	do
	{
		int numfds;
		ecurl_multi_perform(multi_handle, &still_running);
		/* wait for activity, timeout or "nothing" */
		ecurl_multi_wait(multi_handle, NULL, 0, 1000, &numfds);

		/* 'numfds' being zero means either a timeout or no file descriptors to
		 wait for. Try timeout on first occurrence, then assume no file
		 descriptors and no file descriptors to wait for means wait for 100
		 milliseconds. */
		if (!numfds)
		{
			repeats++; /* count number of repeated zero numfds */
			if (repeats > 1)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
			}
		}
		else
		{
			repeats = 0;
		}
	} while (still_running);
	{
		ecurl_multi_cleanup(multi_handle);
		for (size_t i = 0; i < num; ++i)
		{
			//ecurl_easy_setopt(handles[i], CURLOPT_MIMEPOST, NULL);
			//ecurl_easy_setopt(handles[i], CURLOPT_HTTPHEADER, NULL);
			curl_mime_free(mime1[i]);
			curl_easy_cleanup(handles[i]);
			//mime1[i] = NULL;
			if (unlikely(ret[i].length() != 27))
			{
				std::cerr << "response length: " << ret[i].length() << ": "
						<< ret[i] << "\n";
				throw std::runtime_error(
						"upload response length was not 27 bytes long! something went wrong");
			}
			if (unlikely(ret[i][0] != '1' || ret[i][1] != '|'))
			{
				std::cerr << "(invalid) upload response: " << ret[i] << "\n";
				throw std::runtime_error("upload response was invalid!");
			}
			ret[i].erase(0, 2);
		}
		curl_slist_free_all(slist1);
		//slist1 = NULL;
	}
	return ret;
}
string Downloadcacapi::upload(const string& data, const string& savename)
{
	this->last_interaction_time = time(NULL);
	curl_mime *mime1 = NULL;
	curl_mimepart *part1 = NULL;
	struct curl_slist *slist1 = NULL;
	slist1 = ecurl_slist_append(slist1, "X-Requested-With: XMLHttpRequest");
	mime1 = ecurl_mime_init(this->ch);
	part1 = ecurl_mime_addpart(mime1);
	ecurl_mime_data(part1, "", CURL_ZERO_TERMINATED);
	ecurl_mime_name(part1, "days");
	part1 = ecurl_mime_addpart(mime1);
	ecurl_mime_data(part1, "", CURL_ZERO_TERMINATED);
	ecurl_mime_name(part1, "downloads");
	part1 = ecurl_mime_addpart(mime1);
	ecurl_mime_data(part1, "", CURL_ZERO_TERMINATED);
	ecurl_mime_name(part1, "password");
	part1 = ecurl_mime_addpart(mime1);
//curl_mime_filedata(part1, "/dev/null");
	ecurl_mime_data(part1, &data[0], data.length());
	ecurl_mime_filename(part1, savename.c_str());
	ecurl_mime_name(part1, "file");
	ecurl_easy_setopt(this->ch, CURLOPT_MIMEPOST, mime1);
	ecurl_easy_setopt(this->ch, CURLOPT_HTTPHEADER, slist1);
//string response=this->curl_exec("http://dumpinput.ratma.net");
	string response = this->curl_exec(
			"https://download.cloudatcost.com/upload.php");
	ecurl_easy_setopt(this->ch, CURLOPT_MIMEPOST, NULL);
	ecurl_easy_setopt(this->ch, CURLOPT_HTTPHEADER, NULL);
	curl_mime_free(mime1);
	mime1 = NULL; //
	curl_slist_free_all(slist1);
	slist1 = NULL;
	if (unlikely(response.length() != 27))
	{
		std::cerr << "response length: " << response.length() << ": "
				<< response << "\n";
		throw std::runtime_error(
				"upload response length was not 27 bytes long! something went wrong");
	}
	if (unlikely(response[0] != '1' || response[1] != '|'))
	{
		std::cerr << "(invalid) upload response: " << response << "\n";
		throw std::runtime_error("upload response was invalid!");
	}
	response.erase(0, 2);
	return response;
}
void Downloadcacapi::delete_upload(const string& id)
{
	this->last_interaction_time = time(NULL);

	ecurl_easy_setopt(this->ch, CURLOPT_POST, 1);
	ecurl_easy_setopt(this->ch, CURLOPT_COPYPOSTFIELDS,
			string("act=1&filecode=" + urlencode(id)).c_str());
	string response = this->curl_exec(
			"https://download.cloudatcost.com/user/uploaded_files.php");
//    string response=this->curl_exec("http://dumpinput.ratma.net");
	if (unlikely(response.length() != 1 || response[0] != 'y'))
	{
		std::cerr << "response length: " << response.length() << ": "
				<< response << std::endl;
		throw std::runtime_error(
				"failed to delete upload! got invalid response from delete api.");
	}
#ifdef DEBUG
	cerr << "deleted " << id << endl;
#endif
}
future<bool> Downloadcacapi::async_delete_upload(const string& id)
{
	CURL *acurl = ecurl_easy_init();
	ecurl_clone_cookies(this->ch, acurl);
	return std::async([](CURL *acurl, const string id)->bool
	{
		//mhmhmthis->last_interaction_time = time(NULL);

			ecurl_easy_setopt(acurl, CURLOPT_POST, 1);
			ecurl_easy_setopt(acurl, CURLOPT_COPYPOSTFIELDS,
					string("act=1&filecode=" + urlencode(id)).c_str());
			string response;
			ecurl_easy_setopt(acurl,CURLOPT_WRITEFUNCTION,Downloadcacapi::curl_write_hook);
			ecurl_easy_setopt(acurl,CURLOPT_WRITEDATA,&response);
			ecurl_easy_setopt(acurl,CURLOPT_URL,"https://download.cloudatcost.com/user/uploaded_files.php");
			ecurl_easy_perform(acurl);
			curl_easy_cleanup(acurl);
			if (response.length() != 1 || response[0] != 'y')
			{
#ifdef DEBUG
			std::cerr << "Warning: async_delete_upload() failed! invalid response from api! " << " id: " << id << "\n" << "response length: " << response.length() << ": "
			<< response << std::endl;
#endif
			return false;
		}
#ifdef DEBUG
			cerr << ("deleted "+id+"\n") << flush;
#endif
			return true;
		}, acurl, id);
}

Downloadcacapi::Downloadcacapi(const string& username, const string& password) :
		username(username), password(password)
{
	this->ch = ecurl_easy_init();
	ecurl_easy_setopt(this->ch, CURLOPT_WRITEFUNCTION,
			Downloadcacapi::curl_write_hook);
	ecurl_easy_setopt(this->ch, CURLOPT_WRITEDATA, &this->responsebuf);
	ecurl_easy_setopt(this->ch, CURLOPT_AUTOREFERER, 1);
	ecurl_easy_setopt(this->ch, CURLOPT_FOLLOWLOCATION, 1);
	ecurl_easy_setopt(this->ch, CURLOPT_HTTPGET, 1);
	ecurl_easy_setopt(this->ch, CURLOPT_SSL_VERIFYPEER, 0); // fixme?
	ecurl_easy_setopt(this->ch, CURLOPT_CONNECTTIMEOUT, 8);
	//ecurl_easy_setopt(this->ch, CURLOPT_TIMEOUT, 60); // how long to wait for 4096? dunno...
	ecurl_easy_setopt(this->ch, CURLOPT_COOKIEFILE, "");
	ecurl_easy_setopt(this->ch, CURLOPT_TCP_KEEPALIVE, 1L);
	ecurl_easy_setopt(this->ch, CURLOPT_ACCEPT_ENCODING, ""); // this should make login/logout faster, but it might make sector upload/download slower, or just use more cpu.. hmm
	ecurl_easy_setopt(this->ch, CURLOPT_USERAGENT, "cacdrive-dev");
	this->login();
	this->cookie_session_keepalive_thread_curl = ecurl_easy_init();
	ecurl_clone_cookies(this->ch, this->cookie_session_keepalive_thread_curl);
	this->last_interaction_time = time(NULL);
	cookie_session_keepalive_thread =
			std::thread(
					[this]()->void
					{
						string unused_reply_buffer;
						ecurl_easy_setopt(this->cookie_session_keepalive_thread_curl,CURLOPT_WRITEDATA,&unused_reply_buffer);
						ecurl_easy_setopt(this->cookie_session_keepalive_thread_curl,CURLOPT_URL,"https://download.cloudatcost.com/user/settings.php");
						ecurl_easy_setopt(this->cookie_session_keepalive_thread_curl,CURLOPT_HTTPGET,1);
						ecurl_easy_setopt(this->cookie_session_keepalive_thread_curl,CURLOPT_WRITEFUNCTION,Downloadcacapi::curl_write_hook);
						for(;;)
						{
							this_thread::sleep_for(chrono::seconds(1));
							if(this->last_interaction_time==0)
							{
								// 0 is a magic value for `time to shut down`.
								return;
							}
							if(this->last_interaction_time > (time(NULL)-(20*60)))
							{
								continue;
							}
							//cout << "20min ping.. last: " << this->last_interaction_time << " - now: " << time(NULL) << endl;
							//been over 10 minutes since the last interaction, time to send a keepalive ping.
							ecurl_easy_perform(this->cookie_session_keepalive_thread_curl);
							this->last_interaction_time=time(NULL);
							unused_reply_buffer.clear();
						}
					});
} //
Downloadcacapi::~Downloadcacapi()
{
	this->last_interaction_time = 0; // magic value for shut down.
	this->cookie_session_keepalive_thread.join(); // a signal would be faster/better... not sure how to implement that.
	this->logout();
	curl_easy_cleanup(this->ch);
	curl_easy_cleanup(this->cookie_session_keepalive_thread_curl);
}
void Downloadcacapi::login()
{
	ecurl_easy_setopt(this->ch, CURLOPT_HTTPGET, 1);
	this->curl_exec_faster1("https://download.cloudatcost.com/user/login.php"); // just need a cookie session.
	ecurl_easy_setopt(this->ch, CURLOPT_POST, 1);
	ecurl_easy_setopt(this->ch, CURLOPT_COPYPOSTFIELDS,
			string(
					string("username=") + urlencode(this->username)
							+ string("&password=") + urlencode(this->password)
							+ "&submit=").c_str());
	string response = this->curl_exec(
			"https://download.cloudatcost.com/user/manage-check.php");
//    string response=this->curl_exec("dumpinput.ratma.net");
	if (response.find("LOGOUT") == string::npos)
	{
		std::cerr << "len: " << response.length() << " - " << response
				<< std::endl;
		throw runtime_error("failed to login - cannot find the logout button!");
	}
}
void Downloadcacapi::logout()
{
	ecurl_easy_setopt(this->ch, CURLOPT_HTTPGET, 1);
	this->curl_exec("https://download.cloudatcost.com/user/logout.php");
}
string Downloadcacapi::curl_exec(const string& url)
{
	this->responsebuf.clear();
	ecurl_easy_setopt(this->ch, CURLOPT_URL, url.c_str());
	ecurl_easy_perform(this->ch);
	return string(this->responsebuf);
}
void Downloadcacapi::curl_exec_faster1(const string& url)
{
	this->responsebuf.clear();
	ecurl_easy_setopt(this->ch, CURLOPT_URL, url.c_str());
	ecurl_easy_perform(this->ch);
	return;
}
vector<string> Downloadcacapi::get_cookies()
{
	vector<string> ret;
	struct curl_slist *cookies = NULL;
	CURLcode res = curl_easy_getinfo(this->ch, CURLINFO_COOKIELIST, &cookies);
	if (res == CURLE_OK && cookies)
	{
		struct curl_slist *each = cookies;
		while (each)
		{
			ret.push_back(string(string(each->data)));
			each = each->next;
		}
		curl_slist_free_all(cookies);
	}
	return ret;
}
void print_io_cache()
{
	/*
	 struct io_cache_object
	 {
	 time_t mtime;
	 std::string data;
	 //uint64_t sector; is the io_cache key.
	 };
	 std::unordered_map<uint64_t, io_cache_object> io_cache;
	 shared_mutex io_cache_mutex;
	 */
	io_cache_mutex.lock_shared();
	for (const auto& cache : io_cache)
	{
		cout << cache.first << "-" << cache.second.length() << ": \""
				<< cache.second << "\"" << endl;
	}
	io_cache_mutex.unlock_shared();
}

void cac_upload_eventually(const uint64_t sectorpos_in, const uint32_t len,
		const char *buf, FILE *fpin)
{
	static bool inited = false;
	static FILE *fp;
	if (unlikely(!inited))
	{
		inited = true;
		static thread upload_eventually_thread;
		upload_eventually_thread =
				std::thread([&]()->void
				{	//return; // uncomment to disable upload completely.
							Downloadcacapi cac(argv_username,argv_password);
							size_t size;
							for(;;)
							{
								io_cache_mutex.lock_shared();
								size=io_cache.size();
								io_cache_mutex.unlock_shared();
								if(size>0)
								{
									io_cache_mutex.lock();
									{
										// <purgeZeroes>
										for (auto it = io_cache.begin(); it != io_cache.end(); )
										{	// CRASH HERE:
											if(it->second.length()==0)
											{
												cac_update_sectorcode(fp,it->first/SECTOR_SIZE,string(0,'\0'));
												it = io_cache.erase(it);
											}
											else
											{
												++it;
											}
										}
										// </purgeZeroes>
									}
									size=io_cache.size();
									io_cache_mutex.unlock();
									if(size==0)
									{

									}
									else
									{
										io_cache_mutex.lock_shared();
										struct Upload_meta_data_struct
										{
											uint64_t sector;
										};
										vector<Upload_meta_data_struct> upload_meta_data;
										upload_meta_data.reserve(size);
										vector<Downloadcacapi::Upload_multi_arg> upload_args;
										upload_args.reserve(size);
										size=io_cache.size();
										// for c++17 i should do for (const auto & [ key, value ] : map) {}
										// but eclipse gets pissy with `invalid syntax` errors :(
										for (const auto& it : io_cache)
										{
											if(it.second.size()==0)
											{
												continue;
											}
											upload_args.push_back(Downloadcacapi::Upload_multi_arg
													{
														.data=it.second,
														.savename=string("sector_"+to_string((it.first/SECTOR_SIZE))+".zip")
													});
											upload_meta_data.push_back(Upload_meta_data_struct
													{
														.sector=it.first
													});
										}
										io_cache_mutex.unlock_shared();
										const auto& foo=cac.upload_multi(upload_args);
										assert(foo.size()==upload_args.size() && foo.size()==upload_meta_data.size());
										//upload_args.clear(); // would save memory..
										io_cache_mutex.lock();
										size_t len;
										for(ssize_t vi=foo.size()-1;vi>=0;--vi)
										{
											if((len=io_cache[upload_meta_data[vi].sector].length())==0 || 0!=memcmp(&(io_cache[upload_meta_data[vi].sector][0]),&(upload_args[vi].data[0]),SECTOR_SIZE))
											{
												//dammit, cache outdated by the time we managed to upload it.
												cac_delete_eventually(foo[vi]);
												if(len==0)
												{
													io_cache.erase(upload_meta_data[vi].sector);
													cac_update_sectorcode(fp,(upload_meta_data[vi].sector/SECTOR_SIZE),string(0,'\0'));
												}
											}
											else
											{
												io_cache.erase(upload_meta_data[vi].sector);
												cac_update_sectorcode(fp,(upload_meta_data[vi].sector/SECTOR_SIZE),foo[vi]);
											}
											assert(len==0 || len == SECTOR_SIZE);
											//upload_meta_data.pop_back();
											//upload_args.pop_back();
										}
										io_cache_mutex.unlock();
									}
								}
								else
								{
									cout << "upload queue emptied." << endl;
									for(;;)
									{
										io_cache_mutex.lock_shared();
										size=io_cache.size();
										io_cache_mutex.unlock_shared();
										if(size<1)
										{
											std::this_thread::sleep_for(std::chrono::seconds(1));
										}
										else
										{
											break;
										}
									}
									cout << "upload queue no longer empty! (" << size << ")" << endl;
								}
							}
						});
		upload_eventually_thread.detach();
		return;
	}
	else
	{
		fp = fpin;						///ugly hack and fixme,
	}
	{
		assert(
				0 == (sectorpos_in % SECTOR_SIZE)
						&& "sector-unaligned writes are not supported yet.");
		assert(
				0 == (len % SECTOR_SIZE)
						&& "sector-unaligned writes are not supported yet.");
		io_cache_mutex.lock();
		uint32_t bpos = 0;
		for (uint64_t sectorpos_now = sectorpos_in;
				sectorpos_now < (sectorpos_in + len); sectorpos_now +=
						SECTOR_SIZE)
		{
			//cout << "sectorpos_in: " << sectorpos_in << " sectorS: " << sectors << " sectorpos_now: " << sectorpos_now << endl;
			assert((sectorpos_now / SECTOR_SIZE) <= sectors);
			bool zeroes = memory_is_all_zeroes(&buf[bpos], SECTOR_SIZE);
			if (io_cache.count(sectorpos_now))
			{
				if (zeroes)
				{
					io_cache[sectorpos_now].clear();
				}
				else
				{
					io_cache[sectorpos_now].assign(&buf[bpos], SECTOR_SIZE);
				}
			}
			else
			{
//				cout << "inserting sector " << (sectorpos_now / SECTOR_SIZE)
//						<< " / sectorpos: " << sectorpos_now << endl;
				io_cache.insert(
						{ sectorpos_now,
								zeroes ?
										(string(0, '\0')) :
										(string(&buf[bpos], SECTOR_SIZE)) });
			}
			bpos += SECTOR_SIZE;
		}
		io_cache_mutex.unlock();
		return;
	}

//////////////////////////////
//////////////////////////////
//////////////////////////////
//////////////////////////////

	const int64_t start = int64_t(
			floor(double(sectorpos_in) / double(SECTOR_SIZE)));
	const int64_t end = int64_t(
			floor(double(start) + (double(len - 1) / double(SECTOR_SIZE))));
	uint32_t bpos = 0;
	uint64_t i = start;

//////////////////////////////
//////////////////////////////
//////////////////////////////
//////////////////////////////
#ifdef NOPE
//	auto codes = cac_get_sector_codes(pos, len, fp);
//	for (int vi = codes.size() - 1; vi >= 0; --vi)
//	{
////		assert(codes[vi].length() == CAC_CODE_SIZE);
////		// <zeroes>
////		if (memory_is_all_zeroes(&buf[bpos], SECTOR_SIZE))
////		{
////			if (codes[vi][0] != '\0')
////			{
////				cout << "called from " << __FILE__ << ":" << __LINE__ << endl;
////				cac_update_sectorcode(fp, (pos + bpos) / SECTOR_SIZE,
////						string(CAC_CODE_SIZE, 0));
////			}
////			codes.erase(codes.begin() + vi);
////			io_cache_mutex.lock_shared();
////			if (io_cache.count(pos + bpos))
////			{
////				io_cache_mutex.unlock_shared();
////				io_cache_mutex.lock();
////				if (io_cache.count(pos + bpos))
////				{
////					io_cache.erase(pos + bpos); // sure hope this clears out the actual contained objects too... vector would, but unordered_map? not sure
////				}
////				io_cache_mutex.unlock();
////			}
////			else
////			{
////				io_cache_mutex.unlock_shared();
////			}
////		}
////		// </zeroes>
////		else
//		{
//			io_cache_mutex.lock_shared();
//			if (io_cache.count(sector + bpos))
//			{
//				if (0
//						!= memcmp(&buf[bpos],
//								&(io_cache[sector + bpos].data[0]),
//								SECTOR_SIZE))
//				{
//					io_cache_mutex.unlock_shared();
//					io_cache_mutex.lock();
//					if (io_cache.count(sector + bpos)
//							&& 0
//							!= memcmp(&buf[bpos],
//									&(io_cache[sector + bpos].data[0]),
//									SECTOR_SIZE))
//					{
//						if (memory_is_all_zeroes(&buf[bpos], SECTOR_SIZE))
//						{
//							io_cache[sector + bpos].data.assign(&buf[bpos],
//									SECTOR_SIZE);
//							io_cache[sector + bpos].mtime = time(NULL);
//						}
//						io_cache_mutex.unlock();
//						codes.erase(codes.begin() + vi);
//						goto next;
//					}
//					else
//					{
//						io_cache_mutex.unlock_shared();
//						codes.erase(codes.begin() + vi);
//						goto next;
//					}
//				}
//				else
//				{
//					io_cache_mutex.unlock_shared();
//					io_cache_mutex.lock();
//					if (!io_cache.count(sector + bpos))
//					{
//						io_cache.insert(
//								{	sector + bpos, io_cache_object
//									{	.mtime = time(NULL), .data = string(
//												&buf[bpos], SECTOR_SIZE)}}); //
//						codes.erase(codes.begin() + vi);
//					}
//					io_cache_mutex.unlock();
//				}
//			}
//			next:
//			// eclipse formatter needs a comma here.
//			++i;
//			bpos += SECTOR_SIZE;
//		}
//		assert(bpos == len);
//	}
#endif //NOPE
}
void cac_delete_eventually(const string& id)
{
	static mutex delete_queue_mutex;
	static vector<string> delete_queue;
	static bool inited = false;
	if (unlikely(!inited))
	{
		inited = true;
		static thread delete_queue_thread;
		delete_queue_thread = std::thread([&]()->void
		{
			size_t size;
			Downloadcacapi cac(argv_username,argv_password);
			bool saidit=true;
			for(;;)
			{
				do
				{
					delete_queue_mutex.lock();
					size=delete_queue.size();
					if(size>0)
					{
						// optimization note: it'd probably be faster to use cac.async_delete_upload() if there's many objects to delete, hmm
				const string id=std::move(delete_queue[delete_queue.size()-1]);
				delete_queue.pop_back();
				delete_queue_mutex.unlock();
				saidit=false;
				cac.delete_upload(id);
			}
			else
			{
				delete_queue_mutex.unlock();
			}
		}while(size>0);
		if(!saidit)
		{
			saidit=true;
			cout << "delete queue emptied." << endl;
		}
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}
});
		delete_queue_thread.detach();
		return;
	}
	delete_queue_mutex.lock();
	delete_queue.push_back(id);
	delete_queue_mutex.unlock();
}

void init(const int argc, char **argv, const bool onlyapitests)
{
	install_shutdown_signal_handlers();

	atexit(exit_global_cleanup);
	{
		if (argc != 2)
		{
			std::cerr << "usage: " << argv[0] << " path/to/configfile.conf\n";
			cerr << " - or alternatively: " << argv[0]
					<< " path/to/configfile.conf api-tests\n";
			exit(EXIT_FAILURE);
		}
		FILE *conf = fopen(argv[1], "rb");
		if (!conf)
		{
			myerror(EXIT_FAILURE, errno, "unable to open configfile: %s\n",
					argv[1]);
		}
		char *line = NULL;
		size_t sline = 0;
		if (-1 == getline(&line, &sline, conf)
				|| 0 != strcmp("format=1\n", line))
		{
			std::cerr << "first line of config must start with format=1\n"
					<< std::endl;
			exit(EXIT_FAILURE);
		}
		free(line);
		line = NULL;
		sline = 0;
		if (-1 == getline(&line, &sline, conf))
		{
			std::cerr
					<< "failed to read line 2 of config file! (it must exist)\n"
					<< std::endl;
			exit(EXIT_FAILURE);
		}
		free(line);
		line = NULL;
		sline = 0;
		if (-1 == getline(&line, &sline, conf) || !strlen(line))
		{
			std::cerr << "failed to read username on line 3!\n" << std::endl;
			exit(EXIT_FAILURE);
		}
		argv_username = line;
		argv_username.resize(argv_username.length() - 1);
		free(line);
		line = NULL;
		sline = 0;
		if (-1 == getline(&line, &sline, conf) || !strlen(line))
		{
			std::cerr << "failed to read password on line 4!\n" << std::endl;
			exit(EXIT_FAILURE);
		}
		argv_password = line;
		argv_password.resize(argv_password.length() - 1);
		free(line);
		line = NULL;
		sline = 0;
		if (-1 == getline(&line, &sline, conf) || !strlen(line))
		{
			std::cerr << "failed to read number of worker threads on line 5!\n"
					<< std::endl;
			exit(EXIT_FAILURE);
		}
		try
		{
			int tmp = std::atoi(line);
			if (tmp < 1)
			{
				std::cerr
						<< "invalid number of worker threads, must be between 1-"
						<< INT_MAX << ", is " << line << std::endl;
				exit(EXIT_FAILURE);
			}
			number_of_worker_threads = static_cast<uint>(tmp);
		} catch (...)
		{
			std::cerr
					<< "failed to parse number of worker threads on line 5 as an integer! must be an int between 1-"
					<< INT_MAX << ", is: " << line
					<< " (invalid format? out of range?)\n";
			exit(EXIT_FAILURE);
		}
		free(line);
		line = NULL;
		sline = 0;
		if (-1 == getline(&line, &sline, conf) || !strlen(line))
		{
			std::cerr
					<< "failed to read sector index file location on line 6!\n"
					<< std::endl;
			exit(EXIT_FAILURE);
		}
		sectorindex_file = line;
		sectorindex_file.resize(sectorindex_file.length() - 1);
		free(line);
		line = NULL;
		sline = 0;
		if (-1 == getline(&line, &sline, conf) || !strlen(line))
		{
			std::cerr << "failed to read nbd path (/dev/nbdX) on line 7!\n"
					<< std::endl;
			exit(EXIT_FAILURE);
		}
		nbd_path = line;
		if (nbd_path[nbd_path.length() - 1] == '\n')
		{
			nbd_path.resize(nbd_path.length() - 1);
		}
		free(line);
		line = NULL;
		sline = 0;
		if (-1 != getline(&line, &sline, conf))
		{
			std::cerr << "unknown line 8 in config file!\n" << std::endl;
			exit(EXIT_FAILURE);
		}
		free(line);
		line = NULL;
		sline = 0;
		fclose(conf);
		{
			FILE *fp = fopen(sectorindex_file.c_str(), "r+b"); // i don't need to write to it now, but i need to know that i have permissions to open it in read+write mode, so r+b.
			if (!fp)
			{
				myerror(EXIT_FAILURE, errno,
						"unable to open secctorindex file: %s\n",
						sectorindex_file.c_str());
			}
			fseek(fp, 0, SEEK_END);
			sectors = ftello(fp);
			if (sectors < CAC_CODE_SIZE)
			{
				std::cerr << "error: sectorindex must be at minimum "
						<< CAC_CODE_SIZE << " bytes long, is " << sectors
						<< std::endl;
				exit(EXIT_FAILURE);
			}
			if (0 != (sectors % CAC_CODE_SIZE))
			{
				std::cerr << "error: sectorindex size is not a multiple of "
						<< CAC_CODE_SIZE << " bytes, must be corrupt."
						<< std::endl;
				exit(EXIT_FAILURE);
			}
			sectors = sectors / CAC_CODE_SIZE;
			fclose(fp);
		}
		{
			CURLcode c = curl_global_init(CURL_GLOBAL_ALL);
			if (unlikely(c != CURLE_OK))
			{
				throw std::runtime_error(
						curlprettyerror("curl_global_init()", c));
			}
		}

	}
	{
		kernelIPC.nbd_fd = open(nbd_path.c_str(), O_RDWR);
		if (kernelIPC.nbd_fd == -1)
		{
			myerror(EXIT_FAILURE, errno, "unable to open nbd path: %s\n",
					nbd_path.c_str());
		}
	}
	{
		int socks[2];
		const int err = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
		if (unlikely(err == -1))
		{
			myerror(EXIT_FAILURE, errno,
					"Failed to create IPC unix socket pair!! (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) \n");
		}
		kernelIPC.localrequestsocket = socks[0];
		kernelIPC.remoterequestsocket = socks[1];
	}
	if (!onlyapitests)
	{
		// time to start the nbd "doit" thread.
		pthread_t doitthread;
		promise<void> return_before_doingit_promise;
		pthread_attr_t doitthread_attributes;
		{
			int err = pthread_attr_init(&doitthread_attributes);
			if (unlikely(err != 0))
			{
				myerror(EXIT_FAILURE, err,
						"failed pthread_attr_init(&doitthread_attributes); ");
			}
			//1 meg should be plenty. a safeguard against small default stack sizes, and a memory saving feature of big stack sizes..
			//to put things in perspective, if the size of a pointer is 8 bytes (64bit), we can now hold 131,072 pointers.
			// (default on my system is 8 meg)
			err = pthread_attr_setstacksize(&doitthread_attributes,
					1 * 1024 * 1024);
			if (unlikely(err != 0))
			{
				myerror(EXIT_FAILURE, err,
						"failed to set doitthread stack size! ");
			}
		}
		int err;
		err = pthread_create(&doitthread, &doitthread_attributes,
				nbd_doit_thread, &return_before_doingit_promise);
		if (unlikely(err != 0))
		{
			myerror(EXIT_FAILURE, err,
					"pthread_create failed to create the NBD_DO_IT thread!\n");
		}
		//now we wait for doitthread to unlock it..
		return_before_doingit_promise.get_future().get();
		err = pthread_attr_destroy(&doitthread_attributes);
		if (unlikely(err != 0))
		{
			myerror(EXIT_FAILURE, err,
					"failed pthread_attr_destroy(&doitthread_attributes); ");
		}
		err = pthread_detach(doitthread);
		if (unlikely(err != 0))
		{
			myerror(EXIT_FAILURE, err, "failed to detach doitthread\n");
		}
	}

}

void Downloadcacapitests()
{
	using namespace std::chrono;
	milliseconds ms = duration_cast<milliseconds>(
			system_clock::now().time_since_epoch());
#define ugly(){milliseconds noww=duration_cast<milliseconds >(system_clock::now().time_since_epoch());std::cout << double((noww-ms).count())/1000 << "s ";ms=duration_cast<milliseconds >(system_clock::now().time_since_epoch());}
	string tmp;
	string tmp2;
	string uploadcontent = "Hello world!";
	cout << "downloadcacapi tests..\n logging in: " << std::flush;
	Downloadcacapi* cacks = new Downloadcacapi(argv_username, argv_password);
	ugly()
	cout << "done! cookies: ";
	for (auto& cookie : cacks->get_cookies())
	{
		cout << cookie << " - ";
	}
	cout << endl;
	cout << "uploading test.txt: " << std::flush;
	tmp = cacks->upload(uploadcontent, "test.txt");
	ugly()
	cout << "done! upload id: " << tmp << std::endl;
	for (int i = 0; i < 2; ++i)
	{
		cout
				<< "downloading what we just uploaded, using the single download api.. "
				<< std::flush;
		tmp2 = cacks->download(tmp);
		ugly()
		cout << "done! contents: " << tmp2
				<< (tmp2 == uploadcontent ?
						(" (content is intact.)") :
						(" (WARNING: content is corrupt!!!)")) << std::endl;
	}
	cout
			<< "downloading what we just uploaded, 20 times simultaneously using the download_multi api  .. "
			<< std::flush;
	const vector<string> vec =
	{ tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp, tmp,
			tmp, tmp, tmp, tmp, tmp };
	const auto resvec = cacks->download_multi(vec);
	ugly()
	;
	cout << "download complete! checking contents.. " << flush;
	for (const auto& resp : resvec)
	{
		if (resp == uploadcontent)
		{
			cout << "correct.. " << flush;
		}
		else
		{
			cout << "!!!WRONG!!!.. " << flush;
		}
	}
	cout << endl;
	cout << "deleting upload using synchronous api: " << std::flush;
	cacks->delete_upload(tmp);
	ugly()
	cout << "done!" << std::endl;
	cout << "uploading test.txt (again): " << std::flush;
	tmp = cacks->upload(uploadcontent, "test.txt");
	ugly()
	cout << "done!" << std::endl;
	cout << "deleting upload using async api: " << std::flush;
	auto fut = cacks->async_delete_upload(tmp);
	bool aret = fut.get();
	ugly()
	cout << " done! returned value: "
			<< (aret ?
					"true (as expected)" :
					"false (something went wrong! expected true, got false)")
			<< endl;
	cout << "deleting a bogus upload id using async api: " << std::flush;
	auto fut2 = cacks->async_delete_upload("bogus_upload_id");
	bool aret2 = fut2.get();
	ugly()
	cout << " done! returned value: "
			<< (aret2 ?
					"true (something went wrong! expected false, got true)" :
					"false (as expected)") << endl;
	cout << "uploading 20 times using multi_upload api.." << flush;
	const std::vector<Downloadcacapi::Upload_multi_arg> multi_upload_test_20 =
	{ Downloadcacapi::Upload_multi_arg
	{ .data = uploadcontent, .savename = "apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" },
			Downloadcacapi::Upload_multi_arg
			{ .data = uploadcontent, .savename =
					"apitests_test_multi_upload.txt" }, };

	const auto multi_dl_ret = cacks->upload_multi(multi_upload_test_20);
	ugly()
	if (multi_dl_ret.size() != multi_upload_test_20.size())
	{
		cout << " epic fail! gave " << multi_upload_test_20.size()
				<< " arguments to the api, but recieved " << multi_dl_ret.size()
				<< " codes back! " << endl;
	}
	else
	{
		cout << " done! ids: ";
		for (const string& id : multi_dl_ret)
		{
			cout << id << " - ";
		}
		cout << "\n" << " will now delete them all using the async api..";
		vector<future<bool>> promises;
		promises.reserve(multi_dl_ret.size());
		for (const string& id : multi_dl_ret)
		{
			promises.push_back(cacks->async_delete_upload(id));
		}
		// from here on, it'd be better if we used when_any, but it's not accepted/ready yet. http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2014/n4107.html#futures.when_any
		int i = 0;
		for (auto& prom : promises)
		{
			cout
					<< (prom.get() ?
							"deleted.." :
							("!!!FAILED to delete " + multi_dl_ret[i]));
			++i;
		}
		cout << "\n";
		ugly()
		cout << "done!" << endl;
	}

///
	cout << "logging out: " << std::flush;
	delete cacks;
	ugly()
	cout << "done!\n";
#undef ugly
}

void* nbd_doit_thread(void *return_before_doingit_promise)
{
	{
		static bool firstrun = true;
		if (unlikely(!firstrun))
		{
			myerror(EXIT_FAILURE, 1,
					"nbd_doit_thread() was called twice! this should never happen\n");
		}
		firstrun = false;
	}
	nbd_initialization_started = true;
	if (unlikely(
			0 != ioctl(kernelIPC.nbd_fd, NBD_SET_SOCK, kernelIPC.remoterequestsocket)))
	{
		myerror(EXIT_FAILURE, errno,
				"failed to ioctl(kernelIPC.nbd_fd, NBD_SET_SOCK, kernelIPC.global_remoterequestsocket) !\n");
	}
	nbd_initialization_success = true;
	if (unlikely(0 != ioctl(kernelIPC.nbd_fd, NBD_SET_BLKSIZE, BLOCK_SIZE)))
	{
		myerror(EXIT_FAILURE, errno,
				"failed to ioctl(kernelIPC.nbd_fd, NBD_SET_BLKSIZE, %i) !\n",
				BLOCK_SIZE);
	}
	if (unlikely(
			0 != ioctl(kernelIPC.nbd_fd, NBD_SET_SIZE, (sectors*SECTOR_SIZE))))
	{
		myerror(EXIT_FAILURE, errno,
				"failed to ioctl(kernelIPC.nbd_fd, NBD_SET_SIZE:, %zu) !\n",
				(sectors * SECTOR_SIZE));
	}
	install_shutdown_signal_handlers();
//todo: figure out what NBD_SET_SIZE_BLOCKS is for..
//by setting this, we tell the mainthread that we are done setting things up, which the main thread is waiting for.
	(*(promise<void>*) return_before_doingit_promise).set_value();
// note: this could probably be optimized, https://en.cppreference.com/w/cpp/thread/condition_variable
// but given that it's not part of the hot loop... it's not important.
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	cout << "nbdthread waiting for all workers ("
			<< number_of_worker_threads_ready << "/" << number_of_worker_threads
			<< ") to be become ready. (this usually takes a long time - some problem @CAC login system)"
			<< endl;
	while (number_of_worker_threads > number_of_worker_threads_ready)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	assert(number_of_worker_threads == number_of_worker_threads_ready);
	cout << "all workers (" << number_of_worker_threads_ready << "/"
			<< number_of_worker_threads
			<< ") ready, nbdthread starting NBD_DO_IT." << endl;

//should block indefinitely on NBD_DO_IT
	if (unlikely(0 != ioctl(kernelIPC.nbd_fd, NBD_DO_IT)))
	{
		myerror(EXIT_FAILURE, errno,
				"nbd_do_it_thread failed to ioctl(kernelIPC.nbd_fd, NBD_DO_IT) !\n");
	}
	myerror(0, errno,
			"Warning: nbd_do_it_thread thread shutting down, but was supposed to be blocking...\n");
	return NULL;
}

void exit_global_cleanup(void)
{
	static mutex single_exit_global_cleanup_mutex;
	{
		if (unlikely(!single_exit_global_cleanup_mutex.try_lock()))
		{
			myerror(0, errno,
					"Warning: more than 1 thread tried to run exit_global_cleanup! thread id %zu prevented..\n",
					pthread_self());
			return;
		}
	}
	printf("shutting down, cleaning up.. thread doing the cleanup: %zu \n",
			pthread_self());
	if (kernelIPC.nbd_fd != -1)
	{
		if (nbd_initialization_success)
		{
			/*
			 * NBD_DISCONNECT:
			 * NBD_CLEAR_SOCK:
			 * */
			int err = ioctl(kernelIPC.nbd_fd, NBD_CLEAR_SOCK);
			if (err == -1)
			{
				myerror(0, errno, "Warning: NBD_CLEAR_SOCK failed!\n");
			}
			err = ioctl(kernelIPC.nbd_fd, NBD_DISCONNECT);
			if (err == -1)
			{
				myerror(0, errno, "Warning: NBD_DISCONNECT failed!\n");
			}

		}
		if (-1 == close(kernelIPC.nbd_fd))
		{
			myerror(0, errno, "Warning: failed to close the nbd handle!\n");
		}
	}
	if (kernelIPC.remoterequestsocket != -1)
	{
		if (-1 == close(kernelIPC.remoterequestsocket))
		{
			myerror(0, errno,
					"Warning: failed to close the kernelIPC.remoterequestsocket!\n");
		}
	}
	if (kernelIPC.localrequestsocket != -1)
	{
		if (-1 == close(kernelIPC.localrequestsocket))
		{
			myerror(0, errno,
					"Warning: failed to close the kernelIPC.localrequestsocket!\n");
		}
	}
	if (close_me_on_cleanup)
	{
		fclose(close_me_on_cleanup);
	}
	curl_global_cleanup();
}
void shutdown_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
	(void) context;
	myerror(EXIT_FAILURE, errno,
			"received shutdown signal %i (%s) from PID %i / UID %i. shutting down..\n",
			sig, strsignal(sig), (int) siginfo->si_pid, (int) siginfo->si_uid);

}
void install_shutdown_signal_handler(const int sig)
{
//yes, void. i terminate if there's an error.
	struct sigaction act =
	{ 0 };
	act.sa_sigaction = &shutdown_signal_handler;
	act.sa_flags = SA_SIGINFO;
	if (unlikely(-1==sigaction(sig, &act, NULL)))
	{
		myerror(EXIT_FAILURE, errno,
				"failed to install signal handler for %i (%s)\n", sig,
				strsignal(sig));
	}
}
void install_shutdown_signal_handlers(void)
{
#if defined(_POSIX_VERSION)
#if _POSIX_VERSION>=199009L
//daemon mode not supported (yet?)
	install_shutdown_signal_handler(SIGHUP);
	install_shutdown_signal_handler(SIGINT);
	install_shutdown_signal_handler(SIGQUIT);
	install_shutdown_signal_handler(SIGILL);		//?
	install_shutdown_signal_handler(SIGABRT);
	install_shutdown_signal_handler(SIGFPE);		//?
//SIGKILL/SIGSTOP is not catchable anyway
	install_shutdown_signal_handler(SIGSEGV);		//?
	install_shutdown_signal_handler(SIGPIPE);		//?
	install_shutdown_signal_handler(SIGALRM);
	install_shutdown_signal_handler(SIGTERM);
//default action for SIGUSR1/SIGUSR2 is to terminate, so, until i have something better to do with them..
	install_shutdown_signal_handler(SIGUSR1);
	install_shutdown_signal_handler(SIGUSR2);
//ignored: SIGCHLD
#if _POSIX_VERSION >=200112L
	install_shutdown_signal_handler(SIGBUS);		//?
	install_shutdown_signal_handler(SIGPOLL);		//?
	install_shutdown_signal_handler(SIGSYS);		//?
	install_shutdown_signal_handler(SIGTRAP);		//?
//ignored: SIGURG
	install_shutdown_signal_handler(SIGVTALRM);
	install_shutdown_signal_handler(SIGXCPU);	//not sure this 1 is catchable..
	install_shutdown_signal_handler(SIGXFSZ);
#endif
#endif
#endif
//Now there are more non-standard signals who's default action is to terminate the process
// which we probably should look out for, but.... cba now. they shouldn't happen anyway (like some 99% of the list above)
}
struct mybuffer
{
	size_t buffer_size;
	char* buffer;
};
struct myrequest
{
	struct nbd_request nbdrequest;
	struct mybuffer mybuf;
};
struct myreply
{
	struct nbd_reply nbdreply __attribute((packed));
	struct mybuffer mybuf;
};
void print_request_data(const char *initial_message,
		const struct myrequest *request)
{
	return;
	printf("%s\n", initial_message);
	printf("request->magic: %i\n", NTOHL(request->nbdrequest.magic));
	printf("request->type: %i\n", NTOHL(request->nbdrequest.type));
	{
		uint64_t nhandle;
		static_assert(sizeof(nhandle) == sizeof(request->nbdrequest.handle),
				"if this fails, the the code around needs to get updated.");
		memcpy(&nhandle, request->nbdrequest.handle, sizeof(nhandle));
		printf("request->handle: %llu\n", NTOHLL(nhandle));
	}

	printf("request->from: %llu\n", NTOHLL(request->nbdrequest.from));
	printf("request->len: %u\n", NTOHL(request->nbdrequest.len));
}

void* workers_entrypoint(void *workernum_in)
{
	static mutex process_request_mutex;
	const int workernum = *(int*) workernum_in;
	free(workernum_in);
//note: we could either have a fp per thread doing fflush all the time, or we could share a single fp across all threads and mutex lock()/unlock() all the time.. not sure what's best,
// but rolling the lock()/unlock() approach for now.
	static FILE *fp = NULL;
	static mutex single_fopen_lock;
	if (single_fopen_lock.try_lock())
	{
		fp = fopen(sectorindex_file.c_str(), "r+b");	//
		if (unlikely(fp==NULL))
		{
			myerror(EXIT_FAILURE, errno,
					"worker thread failed to fopen sector index file! (which is weird because mainthread did it during initialization without problems...) file: %s\n",
					sectorindex_file.c_str());
		}
		close_me_on_cleanup = fp;
	}

//a resize is unlikely() because it may happen a few times in the beginning,
//but once it reaches the kernel max request/response size (4096*32?), it will never happen again..
//lets hope the cpu catches up on that eventually
// #define putsize(x) _Generic((x), size_t: printf("%zu\n", x), default: assert(!"test requires size_t")) \n putsize (sizeof 0);
#define REALBUF_MINSIZE(minsize){                             \
			static_assert(sizeof(minsize) == sizeof(request.nbdrequest.len), \
"should be a uint32_t..."); \
if (unlikely(realbuffer.buffer_size < minsize)) { \
	free(realbuffer.buffer); \
	realbuffer.buffer = (char*)emalloc(minsize); \
	realbuffer.buffer_size = minsize; \
	request.mybuf = realbuffer; \
	reply.mybuf = realbuffer; \
} \
};
//volatile global variables often cannot be held in cpu registers (for long), and are more difficult to optimize.
//so, make a local copy of it, since it wont change at this point anyway.
	const int localrequestsocket = kernelIPC.localrequestsocket;
	struct myrequest request =
	{ 0 };
	struct myreply reply =
	{ 0 };
	struct mybuffer realbuffer =
	{ 0 };
//32 is NOT random. its the highest i've ever seen from my own local amd64 system.
//the kernel first try blocksize*4. if i return EINVAL, it tries blocksize*1, but if success,
//it tries blocksize*8, then blocksize*16 , then blocksize*32
//and stops there.
//TODO: optimization note: make the socketpair buffer at least MAX(blocksize*32,currentbuffersize);
// optimization note: emulate 4096 blocksize with (4096*32) blocksize @CAC ? maybe =/ could have either negative or positive performance impact, but either way, it would be drastic
	realbuffer.buffer = (char*) emalloc(BLOCK_SIZE * 32);
	realbuffer.buffer_size = BLOCK_SIZE * 32;
	request.mybuf = realbuffer;
	reply.mybuf = realbuffer;
	reply.nbdreply.magic = HTONL(NBD_REPLY_MAGIC);
	reply.nbdreply.error = HTONL(0);
	Downloadcacapi cac(argv_username, argv_password);
	++number_of_worker_threads_ready;
	std::cout << "worker #" << workernum << " ready." << endl;
// note this could probably be optimized, https://en.cppreference.com/w/cpp/thread/condition_variable
// but given that it's not part of the hot loop... it's not important.
	const static auto einval = [&]()->void
	{
		//TODO
		};
	(void) einval;
	while (!nbd_initialization_success)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
// <hotWorkerLoop>
	while (1)
	{
		process_request_mutex.lock();
		const ssize_t bytes_read = recv(localrequestsocket, &request.nbdrequest,
				sizeof(request.nbdrequest),
				MSG_WAITALL);
		if (unlikely(bytes_read == 0))
		{
			cout << "request socket shutting down, worker exiting.\n" << flush;
			break;
		}
		if (unlikely(bytes_read != sizeof(request.nbdrequest)))
		{
			myerror(0, errno,
					"got invalid request! all requests must be at minimum %zu bytes, but got a request with only %zu bytes! reply bytes follow:",
					sizeof(request.nbdrequest), bytes_read);
			if (bytes_read <= 0)
			{
				fprintf(stderr,
						"(not printed because the read size was <=0)\n");
			}
			else
			{
				fwrite(&request.nbdrequest, (size_t) bytes_read, 1,
				stderr);
			}
			fflush(stdout);
			fflush(stderr);
			exit(EXIT_FAILURE);
		}
		if (unlikely(request.nbdrequest.magic!=HTONL(NBD_REQUEST_MAGIC)))
		{
			//todo: einval?
			myerror(EXIT_FAILURE, errno,
					"got invalid request! the request magic contained an invalid value. must be %ul , but got %ul\n",
					HTONL(NBD_REQUEST_MAGIC), HTONL(request.nbdrequest.magic));
		}
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		switch (request.nbdrequest.type)
		{
		case HTONL(NBD_CMD_READ):
		{
#ifdef DEBUG
			print_request_data("GOT A NBD_CMD_READ REQUEST", &request);
#endif
			//let another thread read new requests, as early as possible for performance.
			process_request_mutex.unlock();

			static_assert(
					sizeof(reply.nbdreply.handle)
					== sizeof(request.nbdrequest.handle),
					"if this fails, the code needs to get updated.");
			memcpy(reply.nbdreply.handle, request.nbdrequest.handle,
					sizeof(request.nbdrequest.handle));
			// likely() because i'm not sure the kernel
			// EVER will request to read 0 bytes. but IF, against expectation, it ever does,
			// the code inside would probably fail.
			const uint32_t len = NTOHL(request.nbdrequest.len);
			if (unlikely(0 != (len % SECTOR_SIZE)))
			{
				//todo: einval
				myerror(EXIT_FAILURE, 0,
						"got a sector-unaligned read! not yet supported!");
			}
			if (likely(len != 0))
			{
				REALBUF_MINSIZE(len);
				const uint64_t pos = NTOHLL(request.nbdrequest.from);
				if (unlikely(0 != (pos % SECTOR_SIZE)))
				{
					//todo: einval
					myerror(EXIT_FAILURE, 0,
							"got a sector-unaligned-length read! not yet supported!");
				}
				if (unlikely(pos > (sectors * SECTOR_SIZE)))
				{
					//todo: einval
					myerror(EXIT_FAILURE, 0,
							"kernel tried to read outside of the last sector!");
				}

				cac_get_data(cac, pos, len, realbuffer.buffer, fp);
			}
			{
				reply.nbdreply.error = HTONL(0);
				nbdreply(localrequestsocket, &reply.nbdreply,
						sizeof(reply.nbdreply), reply.mybuf.buffer, len);
			}
			break;
		}
		case HTONL(NBD_CMD_WRITE):
		{
#ifdef DEBUG
			print_request_data("GOT A NBD_CMD_WRITE REQUEST\n", &request);
#endif
			const uint32_t len = NTOHL(request.nbdrequest.len);
			if (unlikely(0 != (len % SECTOR_SIZE)))
			{
				//todo: einval
				myerror(EXIT_FAILURE, 0,
						"got a sector-unaligned-length write! not yet supported!");
			}
			REALBUF_MINSIZE(len);
			const uint64_t pos = NTOHLL(request.nbdrequest.from);
			if (unlikely(0 != (pos % SECTOR_SIZE)))
			{
				//todo: einval
				myerror(EXIT_FAILURE, 0,
						"got a sector-unaligned-length write! not yet supported!");
			}
			if (unlikely(pos > (sectors * SECTOR_SIZE)))
			{
				//todo: einval
				myerror(EXIT_FAILURE, 0,
						"kernel tried to write outside of the last sector!");
			}
			const ssize_t bytes_read = recv(localrequestsocket,
					realbuffer.buffer, len, MSG_WAITALL);
			if (unlikely(bytes_read != len))
			{
				myerror(0, errno,
						"failed to read all the bytes of a WRITE request! the server said the request was %i bytes long, but could only read %zd bytes. read bytes follow:\n",
						request.nbdrequest.len, bytes_read);
				if (bytes_read <= 0)
				{
					fprintf(stderr,
							"(not printed because the read size was <=0)\n");
				}
				else
				{
					fwrite(&request.mybuf.buffer, (size_t) bytes_read, 1,
					stderr);
				}
				fflush(stdout);
				fflush(stderr);
				exit(EXIT_FAILURE);
			}
			//let another thread read new requests
			process_request_mutex.unlock();
			memcpy(reply.nbdreply.handle, request.nbdrequest.handle,
					sizeof(request.nbdrequest.handle));

			{
				//cac_write_data(cac, pos, len, realbuffer.buffer, fp);
				cac_upload_eventually(pos, len, realbuffer.buffer, fp);
				reply.nbdreply.error = HTONL(0);
				nbdreply(localrequestsocket, &reply.nbdreply,
						sizeof(reply.nbdreply), NULL, 0);

			}
			break;
		}
//		case HTONL(NBD_CMD_DISC):
//		{
//#ifdef DEBUG
//			printf("GOT A NBD_CMD_DISC REQUEST\n");
//			print_request_data(&request);
//#endif
//			//let another thread read new requests
//			process_request_mutex.unlock();
//			//this is a disconnect request..
//			//there is no reply to NBD_CMD_DISC...
//			// idk what to do here, terminate?
//			break;
//		}
//		case HTONL(NBD_CMD_FLUSH):
//		{
//#ifdef DEBUG
//			printf("GOT A NBD_CMD_FLUSH REQUEST\n");
//			print_request_data(&request);
//#endif
//			process_request_mutex.unlock();
//			reply.nbdreply.error = HTONL(0);
//			static_assert(
//					sizeof(reply.nbdreply.handle)
//					== sizeof(request.nbdrequest.handle),
//					"if this fails, the code needs to get updated.");
//			memcpy(reply.nbdreply.handle, request.nbdrequest.handle,
//					sizeof(request.nbdrequest.handle));
//			nbdreply(localrequestsocket, &reply.nbdreply,
//					sizeof(reply.nbdreply), NULL, 0);
////			ewrite(localrequestsocket, &reply.myreply.nbdreply,
////					sizeof(reply.myreply.nbdreply));
//			break;
//		}
//		case HTONL(NBD_CMD_TRIM):
//		{
//#ifdef DEBUG
//			printf("GOT A NBD_CMD_TRIM REQUEST\n");
//			print_request_data(&request);
//#endif
//			process_request_mutex.unlock();
//			reply.nbdreply.error = HTONL(0);
//			static_assert(
//					sizeof(reply.nbdreply.handle)
//					== sizeof(request.nbdrequest.handle),
//					"if this fails, the code needs to get updated.");
//			memcpy(reply.nbdreply.handle, request.nbdrequest.handle,
//					sizeof(request.nbdrequest.handle));
//			nbdreply(localrequestsocket, &reply.nbdreply,
//					sizeof(reply.nbdreply), NULL, 0);
//			break;
//		}
		default:
		{
			//implement NBD_CMD_WRITE_ZEROES ? its not accepted mainline, experimental, etcetc
			//implement NBD_CMD_STRUCTURED_REPLY? same as above
			//implement NBD_CMD_INFO ? same as above
			//implement NBD_CMD_CACHE ? same as above
			//send EINVAL?
			// ¯\_(ツ)_/¯
			print_request_data("unknown packet!", &request);
			myerror(0, errno,
					"Warning: got a request type i did not understand!: %ul len: - this could mean trouble. -  (see the source code for a list of requests i DO understand, in the switch case's)",
					NTOHL(request.nbdrequest.type));
			memcpy(reply.nbdreply.handle, request.nbdrequest.handle,
					sizeof(request.nbdrequest.handle));
			const uint32_t len = NTOHL(request.nbdrequest.len);
			if (len > 0)
			{
				REALBUF_MINSIZE(len);
				const ssize_t bytes_read = recv(localrequestsocket,
						&request.nbdrequest, sizeof(request.nbdrequest),
						MSG_WAITALL);
				if (unlikely(bytes_read != len))
				{
					myerror(EXIT_FAILURE, errno,
							"fatal error: got unknown command with length %i, tried to read the full length of the command but could only read the first %lu byte(s)",
							len, bytes_read);
				}
			}
			process_request_mutex.unlock();
			reply.nbdreply.error = HTONL(EINVAL); // wait, should it be EINVAL or -EINVAL ? i don't know.
			nbdreply(localrequestsocket, &reply.nbdreply,
					sizeof(reply.nbdreply),
					NULL, 0);
			break;
		}
		}

		///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
		///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	}
//</hotWorkerLoop>
	{
		free(realbuffer.buffer);
		static mutex fclose_once_mutex;
		if (fclose_once_mutex.try_lock())
		{
			const int err = fclose(fp);
			if (unlikely(err != 0))
			{
				myerror(0, errno,
						"Warning: worker thread shutting down & cleaning up failed to close sectorindex file handle! weird.");
			}
		}
	}
	return NULL;        //?? pthread demands we return void*
#undef REALBUF_MINSIZE
}
// unfortunately this part has to be synced between threads.
void nbdreply(const int fd, const void *buf1, const size_t buf1_size,
		const void *buf2, const size_t buf2_size)
{
	static mutex nbdreplymutex;
	nbdreplymutex.lock();
	{
		size_t written_total = 0;
		while (written_total < buf1_size)
		{
			const ssize_t written = write(fd,
					&(((const char*) buf1)[written_total]),
					buf1_size - written_total);
			if (unlikely(written < 0))
			{
				myerror(EXIT_FAILURE, errno, "nbdreply write 1 returned <0!!\n");
			}
			written_total += (size_t) written;
		}
	}
	{
		size_t written_total = 0;
		while (written_total < buf2_size)
		{
			const ssize_t written = write(fd,
					&(((const char*) buf2)[written_total]),
					buf2_size - written_total);
			if (unlikely(written < 0))
			{
				myerror(EXIT_FAILURE, errno, "nbdreply write 2 returned <0!!\n");
			}
			written_total += (size_t) written;
		}
	}
	nbdreplymutex.unlock();
	return;
}

void cac_get_data(Downloadcacapi& cac, const uint64_t pos, const uint32_t len,
		char* buf, FILE *fp)
{
//memset(buf,'A',len);return;
	if (unlikely((pos % SECTOR_SIZE) != 0))
	{
		myerror(EXIT_FAILURE, 1,
				"kernel tried to do an sector-unaligned-position read! that is not yet supported (code to handle it is not yet written). pos: %lu len: %u",
				pos, len);
	}
	if (unlikely((len % SECTOR_SIZE) != 0))
	{
		myerror(EXIT_FAILURE, 1,
				"kernel tried to do an sector-unaligned-length read! that is not yet supported (code to handle it is not yet written). pos: %lu len: %u",
				pos, len);
	}
	const int start = int(floor(double(pos) / double(SECTOR_SIZE)));
	const int end = int(
			floor(double(start) + (double(len - 1) / double(SECTOR_SIZE))));

	auto codes = cac_get_sector_codes(pos, len, fp);
	uint64_t bpos = (codes.size() * SECTOR_SIZE);
	uint64_t i = end;
	vector<array<uint64_t, 2>> need_to_download;
	need_to_download.reserve(codes.size()); //worst case scenario (but probably not rare), 0 empty sectors & nothing in io_cache
	for (ssize_t vi = codes.size() - 1; vi >= 0; --vi)
	{
		assert(codes[vi].length() == CAC_CODE_SIZE);
		bpos -= SECTOR_SIZE;
		io_cache_mutex.lock_shared();
		if (io_cache.count(i * SECTOR_SIZE))
		{
			sector_copy(io_cache[i * SECTOR_SIZE], &buf[bpos]);
			io_cache_mutex.unlock_shared();
			codes.erase(codes.begin() + vi);
		}
		else
		{
			io_cache_mutex.unlock_shared();
			if (codes[vi][0] == '\0')
			{
				memset(&buf[bpos], 0, SECTOR_SIZE);
				codes.erase(codes.begin() + vi);
			}
			else
			{
				need_to_download.push_back(array<uint64_t, 2>
				{ i, bpos });
			}
		}
		--i;
	}
	assert(bpos == 0);
	{
		int vi = codes.size() - 1;
		for (const string& data : cac.download_multi(codes))
		{
			assert(data.length() == SECTOR_SIZE);
			if (memory_is_all_zeroes((const unsigned char*) &data[0],
					data.length()))
			{
				cout << "zeroes here shouldn't really happen, called from "
						<< __FILE__ << ":" << __LINE__ << endl;
				cac_update_sectorcode(fp, need_to_download[vi][0],
						string(0, '\0'));
			}
			sector_copy(data, &buf[need_to_download[vi][1]]);
			--vi;
		}
	}
}
void cac_write_data(Downloadcacapi& cac, const uint64_t pos, const uint32_t len,
		const char *buf, FILE *fp)
{
	__builtin_unreachable();
	myerror(EXIT_FAILURE, 1, "no code should call cac_write_data() now!");
	if (unlikely((pos % SECTOR_SIZE) != 0))
	{
		myerror(EXIT_FAILURE, 1,
				"kernel tried to do an sector-unaligned-position write! that is not yet supported (code to handle it is not yet written). pos: %lu len: %u",
				pos, len);
	}
	if (unlikely((len % SECTOR_SIZE) != 0))
	{

		myerror(EXIT_FAILURE, 1,
				"kernel tried to do an sector-unaligned-length write! that is not yet supported (code to handle it is not yet written). pos: %lu len: %u",
				pos, len);
	}
	const int start = int(floor(double(pos) / double(SECTOR_SIZE)));
	const int end = int(
			floor(double(start) + (double(len - 1) / double(SECTOR_SIZE))));

	uint32_t bpos = 0;
	uint64_t i = start;
	auto codes = cac_get_sector_codes(pos, len, fp);
	vector<uint64_t> need_to_upload;
	vector<Downloadcacapi::Upload_multi_arg> need_to_upload_args;
	need_to_upload.reserve(codes.size()); // worst case (but not rare) scenario: 0 empty blocks.
	need_to_upload_args.reserve(need_to_upload.size());
	for (int vi = codes.size() - 1; vi >= 0; --vi)
	{
		assert(codes[vi].length() == CAC_CODE_SIZE);
		if (memory_is_all_zeroes((const unsigned char*) &buf[bpos],
				SECTOR_SIZE))
		{
			if (codes[vi][0] != '\0')
			{
				cout << "called from " << __FILE__ << ":" << __LINE__ << endl;
				cac_update_sectorcode(fp, i, string(0, '\0'));
			}
			codes.erase(codes.begin() + vi);
		}
		else
		{
			need_to_upload.push_back(i);
			need_to_upload_args.push_back(
					{ .data = string(&buf[bpos], SECTOR_SIZE), .savename =
							string("sector_" + to_string(pos + bpos) + ".zip") });
		}
		++i;
		bpos += SECTOR_SIZE;
	}
	assert(bpos == len);
	assert(need_to_upload.size() == need_to_upload_args.size());
	if (need_to_upload.size() > 0)
	{
		const auto newcodes = cac.upload_multi(need_to_upload_args);
		assert(need_to_upload.size() == newcodes.size());
		for (int vi = need_to_upload.size() - 1; vi >= 0; --vi)
		{
			assert(newcodes[vi].size() == CAC_CODE_SIZE);
			cout << "called from " << __FILE__ << ":" << __LINE__ << endl;
			cac_update_sectorcode(fp, need_to_upload[vi], newcodes[vi]);
		}
	}

}
///
vector<string> cac_get_sector_codes(const size_t pos, const size_t length,
		FILE *fp)
{
//pos and length is guaranteed to be sector-aligned at this point.
	vector<string> ret;
	const int number_of_sectors = int(ceil(float(length) / float(BLOCK_SIZE)));
	ret.reserve(number_of_sectors);
	const int start = int(floor(double(pos) / double(SECTOR_SIZE)));
	const int end = int(
			floor(double(start) + (double(length - 1) / double(SECTOR_SIZE))));
	char buf[CAC_CODE_SIZE];
// this lock()/unlock() could be done on every iteration, but i'm not sure that would go any faster.
	sector_readwrite_mutex.lock();
	for (int i = start; i <= end; ++i)
	{
		{
			const int err = fseek(fp, (i * CAC_CODE_SIZE), SEEK_SET);
			if (unlikely(err != 0))
			{
				myerror(EXIT_FAILURE, err,
						"failed to seek to %i in sector file %s",
						(i * CAC_CODE_SIZE), sectorindex_file.c_str());
			}
		}
		{
			const size_t read = fread(buf, 1, CAC_CODE_SIZE, fp);
			if (unlikely(CAC_CODE_SIZE != read))
			{
				myerror(EXIT_FAILURE, errno,
						"tried to read cac code which is %i bytes from sectorindex pos %li, but could only read the first %zu byte(s). ferror: %i",
						CAC_CODE_SIZE, ftello(fp), read, ferror(fp));
			}
			ret.push_back(string(buf, CAC_CODE_SIZE));
		}
	}
	sector_readwrite_mutex.unlock();
	return ret;
}

void cac_update_sectorcode(FILE *fp, const uint64_t sectornum,
		const string& newcode)
{
	assert(newcode.length() == CAC_CODE_SIZE || newcode.length() == 0);
	assert(sectornum <= sectors);
#ifdef DEBUG
	cerr << "updating sectorcode #" << sectornum << ": " << newcode << " ("
			<< string_to_hex(newcode) << ") " << endl;
#endif
	char oldcode[CAC_CODE_SIZE];
	sector_readwrite_mutex.lock();
	efseek(fp, sectornum * CAC_CODE_SIZE, SEEK_SET);
	size_t read = fread(oldcode, 1, CAC_CODE_SIZE, fp);
	if (unlikely(CAC_CODE_SIZE != read))
	{
		const int original_errno = errno; // errno/ferror can be modified by ftell.
		const auto original_ferror = ferror(fp);
		const auto pos = ftell(fp);
		myerror(EXIT_FAILURE, original_errno,
				string(
						"cac_update_sectorcode() failed to read "
								+ to_string(CAC_CODE_SIZE)
								+ " bytes from sectorindex file! could only read the first "
								+ to_string(read) + " bytes. ferror: "
								+ to_string(original_ferror) + " pos: "
								+ to_string(pos) + " sectornum: "
								+ to_string(sectornum)).c_str());
	}
	if (newcode.length() == 0)
	{
		if (oldcode[0] != '\0')
		{
			cac_delete_eventually(string(oldcode, CAC_CODE_SIZE));
			efseek(fp, sectornum * CAC_CODE_SIZE, SEEK_SET);
			memset(oldcode, '\0', CAC_CODE_SIZE); // just using it as a 0-buffer now.
			efwrite(&newcode[0], 1, CAC_CODE_SIZE, fp);
		}
		else
		{
			// new and old code is 0000, do nothing.
		}
	}
	else
	{
		if (0 != memcmp(&newcode[0], oldcode, CAC_CODE_SIZE))
		{
			efseek(fp, sectornum * CAC_CODE_SIZE, SEEK_SET);
			efwrite(&newcode[0], 1, CAC_CODE_SIZE, fp);
			if (oldcode[0] != '\0')
			{
				cac_delete_eventually(string(oldcode, CAC_CODE_SIZE));
			}
		}
	}
	sector_readwrite_mutex.unlock();
}

void start_worker_threads()
{
	{
		static bool firstrun = true;
		if (unlikely(!firstrun))
		{
			myerror(EXIT_FAILURE, 0,
					"error: tried to run start_worker_threads() twice! should never happen.\n");
		}
		firstrun = false;
	}
	cac_delete_eventually("just initializing the deleter thread.");
	cac_upload_eventually(0, 0, "just initializing the uploader thread.",
	NULL);
	pthread_attr_t worker_attributes;
	{
		int err = pthread_attr_init(&worker_attributes);
		if (unlikely(err != 0))
		{
			myerror(EXIT_FAILURE, err,
					"failed pthread_attr_init(&worker_attributes); ");
		}
		//0.5 meg should be plenty.
		// (default on my system is 8 meg, so this saves 7.5 meg per worker on my system.)
		err = pthread_attr_setstacksize(&worker_attributes, 512 * 1024);
		if (unlikely(err != 0))
		{
			myerror(EXIT_FAILURE, err,
					"failed to set worker thread stack size! ");
		}
	}
	{
		std::cout << "starting " << number_of_worker_threads
				<< " worker thread(s).." << std::flush;
		for (uint i = 0; i < number_of_worker_threads; ++i)
		{
			pthread_t worker;
			void *arg = malloc(sizeof(int));
			if (unlikely(!arg))
			{
				myerror(EXIT_FAILURE, errno,
						"failed to allocate memory for worker thread argument!");
			}
			*(int*) arg = (i + 1);
			const int err = pthread_create(&worker, &worker_attributes,
					workers_entrypoint, arg);
			if (unlikely(err != 0))
			{
				myerror(EXIT_FAILURE, errno,
						"failed to create worker thread #%i", i);
			}
		}
		std::cout << ". done." << std::endl;
	}
	{
		const int err = pthread_attr_destroy(&worker_attributes);
		if (unlikely(err != 0))
		{
			myerror(EXIT_FAILURE, err,
					"failed pthread_attr_destroy(&worker_attributes); !");
		}
	}
}
int main(int argc, char **argv)
{
	const bool onlyapitests = (argc == 3 && 0 == strcmp(argv[2], "api-tests"));
	if (onlyapitests)
	{
		argc = 2;
	}
	init(argc, argv, onlyapitests);
//    std::cout << "username: " << argv_username << " - password: " << argv_password<<std::endl;
	if (onlyapitests)
	{
		Downloadcacapitests();
	}
	else
	{
		start_worker_threads();
		cout << "pausing mainthread.." << endl;
		pause();
		cout << "Hello world!" << endl;
	}
	return 0;
}
