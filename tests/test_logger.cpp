#include "Test.hpp"
#include "core/Logger.hpp"
int wmain(int argc,wchar_t** argv) {
    if(argc==2) {
        Core::Logger::SetLevel(Core::LogLevel::Debug);
        std::vector<std::thread> writers;
        for(int t=0;t<4;++t) writers.emplace_back([] { for(int i=0;i<25;++i) Core::Logger::Info("record\nwith-newline"); });
        for(auto& writer:writers) writer.join();
        assert(std::filesystem::u8path(Core::Logger::GetLogDirectoryPath())==std::filesystem::path(argv[1]));
        auto file=*std::filesystem::directory_iterator(argv[1]);
        auto name=file.path().filename().wstring(); assert(name.rfind(L"proxy-",0)==0 && name.size()==18);
        std::ifstream log(file.path()); std::string line; int count=0;
        while(std::getline(log,line)) { assert(line.find("record with-newline")!=std::string::npos); ++count; }
        assert(count==100); return 0;
    }
    TestDirectory tmp;
    auto host=tmp.path/L"host"; std::filesystem::create_directories(host);
    std::ofstream(host/L"logs")<<"block the preferred log directory";
    wchar_t current[32768]{}; GetModuleFileNameW(nullptr,current,32768);
    auto executable=host/L"logger.exe"; std::filesystem::copy_file(current,executable);
    auto local=tmp.path/L"local"; auto temp=tmp.path/L"temp";
    std::filesystem::create_directories(temp);
    SetEnvironmentVariableW(L"LOCALAPPDATA",local.c_str()); SetEnvironmentVariableW(L"TEMP",temp.c_str()); SetEnvironmentVariableW(L"TMP",temp.c_str());
    for(int fallback=0;fallback<2;++fallback) {
        if(fallback) {
            std::filesystem::remove_all(local);
            std::filesystem::create_directories(local);
            std::ofstream(local/L"codex-proxy")<<"block LOCALAPPDATA";
        }
        auto expected=fallback?temp/L"codex-proxy-logs":local/L"codex-proxy/logs";
        auto capture=tmp.path/(fallback?L"stdout2.txt":L"stdout1.txt");
        SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
        HANDLE output=CreateFileW(capture.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&sa,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr); assert(output!=INVALID_HANDLE_VALUE);
        std::wstring command=L"\""+executable.wstring()+L"\" \""+expected.wstring()+L"\"";
        STARTUPINFOW si{}; si.cb=sizeof(si); si.dwFlags=STARTF_USESTDHANDLES;
        si.hStdOutput=output; si.hStdError=output; si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
        PROCESS_INFORMATION pi{};
        assert(CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,0,nullptr,nullptr,&si,&pi));
        assert(WaitForSingleObject(pi.hProcess,10000)==WAIT_OBJECT_0);
        DWORD exit=0; assert(GetExitCodeProcess(pi.hProcess,&exit) && exit==0);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(output);
        assert(std::filesystem::file_size(capture)==0);
    }
}
