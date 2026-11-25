// Typed lazy forwarding to the system TDH. Never load it from DllMain.
#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
#include <mutex>
#include <string>

template<class Function> Function SystemExport(const char* name) {
    static HMODULE system = []() -> HMODULE {
        wchar_t directory[32768]{};
        UINT count = GetSystemDirectoryW(directory, 32768);
        if (!count || count >= 32768) return nullptr;
        auto path = std::wstring(directory) + L"\\tdh.dll";
        return LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }();
    return system ? reinterpret_cast<Function>(GetProcAddress(system, name)) : nullptr;
}
extern "C" TDHSTATUS WINAPI Shim_TdhCreatePayloadFilter(LPCGUID ProviderGuid, PCEVENT_DESCRIPTOR EventDescriptor, BOOLEAN EventMatchANY, ULONG PayloadPredicateCount, PPAYLOAD_FILTER_PREDICATE PayloadPredicates, PVOID* PayloadFilter) {
    static auto function = SystemExport<decltype(&TdhCreatePayloadFilter)>("TdhCreatePayloadFilter");
    return function ? function(ProviderGuid, EventDescriptor, EventMatchANY, PayloadPredicateCount, PayloadPredicates, PayloadFilter) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhDeletePayloadFilter(PVOID* PayloadFilter) {
    static auto function = SystemExport<decltype(&TdhDeletePayloadFilter)>("TdhDeletePayloadFilter");
    return function ? function(PayloadFilter) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhAggregatePayloadFilters(ULONG PayloadFilterCount, PVOID* PayloadFilterPtrs, PBOOLEAN EventMatchALLFlags, PEVENT_FILTER_DESCRIPTOR EventFilterDescriptor) {
    static auto function = SystemExport<decltype(&TdhAggregatePayloadFilters)>("TdhAggregatePayloadFilters");
    return function ? function(PayloadFilterCount, PayloadFilterPtrs, EventMatchALLFlags, EventFilterDescriptor) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhCleanupPayloadEventFilterDescriptor(PEVENT_FILTER_DESCRIPTOR EventFilterDescriptor) {
    static auto function = SystemExport<decltype(&TdhCleanupPayloadEventFilterDescriptor)>("TdhCleanupPayloadEventFilterDescriptor");
    return function ? function(EventFilterDescriptor) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhGetEventInformation(PEVENT_RECORD Event, ULONG TdhContextCount, PTDH_CONTEXT TdhContext, PTRACE_EVENT_INFO Buffer, PULONG BufferSize) {
    static auto function = SystemExport<decltype(&TdhGetEventInformation)>("TdhGetEventInformation");
    return function ? function(Event, TdhContextCount, TdhContext, Buffer, BufferSize) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhGetEventMapInformation(PEVENT_RECORD pEvent, PWSTR pMapName, PEVENT_MAP_INFO pBuffer, ULONG* pBufferSize) {
    static auto function = SystemExport<decltype(&TdhGetEventMapInformation)>("TdhGetEventMapInformation");
    return function ? function(pEvent, pMapName, pBuffer, pBufferSize) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhGetPropertySize(PEVENT_RECORD pEvent, ULONG TdhContextCount, PTDH_CONTEXT pTdhContext, ULONG PropertyDataCount, PPROPERTY_DATA_DESCRIPTOR pPropertyData, ULONG* pPropertySize) {
    static auto function = SystemExport<decltype(&TdhGetPropertySize)>("TdhGetPropertySize");
    return function ? function(pEvent, TdhContextCount, pTdhContext, PropertyDataCount, pPropertyData, pPropertySize) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhGetProperty(PEVENT_RECORD pEvent, ULONG TdhContextCount, PTDH_CONTEXT pTdhContext, ULONG PropertyDataCount, PPROPERTY_DATA_DESCRIPTOR pPropertyData, ULONG BufferSize, PBYTE pBuffer) {
    static auto function = SystemExport<decltype(&TdhGetProperty)>("TdhGetProperty");
    return function ? function(pEvent, TdhContextCount, pTdhContext, PropertyDataCount, pPropertyData, BufferSize, pBuffer) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhEnumerateProviders(PPROVIDER_ENUMERATION_INFO pBuffer, ULONG* pBufferSize) {
    static auto function = SystemExport<decltype(&TdhEnumerateProviders)>("TdhEnumerateProviders");
    return function ? function(pBuffer, pBufferSize) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhEnumerateProvidersForDecodingSource(DECODING_SOURCE filter, PROVIDER_ENUMERATION_INFO* buffer, ULONG bufferSize, ULONG* bufferRequired) {
    static auto function = SystemExport<decltype(&TdhEnumerateProvidersForDecodingSource)>("TdhEnumerateProvidersForDecodingSource");
    return function ? function(filter, buffer, bufferSize, bufferRequired) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhQueryProviderFieldInformation(LPGUID pGuid, ULONGLONG EventFieldValue, EVENT_FIELD_TYPE EventFieldType, PPROVIDER_FIELD_INFOARRAY pBuffer, ULONG* pBufferSize) {
    static auto function = SystemExport<decltype(&TdhQueryProviderFieldInformation)>("TdhQueryProviderFieldInformation");
    return function ? function(pGuid, EventFieldValue, EventFieldType, pBuffer, pBufferSize) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhEnumerateProviderFieldInformation(LPGUID pGuid, EVENT_FIELD_TYPE EventFieldType, PPROVIDER_FIELD_INFOARRAY pBuffer, ULONG* pBufferSize) {
    static auto function = SystemExport<decltype(&TdhEnumerateProviderFieldInformation)>("TdhEnumerateProviderFieldInformation");
    return function ? function(pGuid, EventFieldType, pBuffer, pBufferSize) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhEnumerateProviderFilters(LPGUID Guid, ULONG TdhContextCount, PTDH_CONTEXT TdhContext, ULONG* FilterCount, PPROVIDER_FILTER_INFO* Buffer, ULONG* BufferSize) {
    static auto function = SystemExport<decltype(&TdhEnumerateProviderFilters)>("TdhEnumerateProviderFilters");
    return function ? function(Guid, TdhContextCount, TdhContext, FilterCount, Buffer, BufferSize) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhLoadManifest(PWSTR Manifest) {
    static auto function = SystemExport<decltype(&TdhLoadManifest)>("TdhLoadManifest");
    return function ? function(Manifest) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhLoadManifestFromMemory(LPCVOID pData, ULONG cbData) {
    static auto function = SystemExport<decltype(&TdhLoadManifestFromMemory)>("TdhLoadManifestFromMemory");
    return function ? function(pData, cbData) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhUnloadManifest(PWSTR Manifest) {
    static auto function = SystemExport<decltype(&TdhUnloadManifest)>("TdhUnloadManifest");
    return function ? function(Manifest) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhUnloadManifestFromMemory(LPCVOID pData, ULONG cbData) {
    static auto function = SystemExport<decltype(&TdhUnloadManifestFromMemory)>("TdhUnloadManifestFromMemory");
    return function ? function(pData, cbData) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhFormatProperty(PTRACE_EVENT_INFO EventInfo, PEVENT_MAP_INFO MapInfo, ULONG PointerSize, USHORT PropertyInType, USHORT PropertyOutType, USHORT PropertyLength, USHORT UserDataLength, PBYTE UserData, PULONG BufferSize, PWCHAR Buffer, PUSHORT UserDataConsumed) {
    static auto function = SystemExport<decltype(&TdhFormatProperty)>("TdhFormatProperty");
    return function ? function(EventInfo, MapInfo, PointerSize, PropertyInType, PropertyOutType, PropertyLength, UserDataLength, UserData, BufferSize, Buffer, UserDataConsumed) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhOpenDecodingHandle(PTDH_HANDLE Handle) {
    static auto function = SystemExport<decltype(&TdhOpenDecodingHandle)>("TdhOpenDecodingHandle");
    return function ? function(Handle) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhSetDecodingParameter(TDH_HANDLE Handle, PTDH_CONTEXT TdhContext) {
    static auto function = SystemExport<decltype(&TdhSetDecodingParameter)>("TdhSetDecodingParameter");
    return function ? function(Handle, TdhContext) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhGetDecodingParameter(TDH_HANDLE Handle, PTDH_CONTEXT TdhContext) {
    static auto function = SystemExport<decltype(&TdhGetDecodingParameter)>("TdhGetDecodingParameter");
    return function ? function(Handle, TdhContext) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhGetWppProperty(TDH_HANDLE Handle, PEVENT_RECORD EventRecord, PWSTR PropertyName, PULONG BufferSize, PBYTE Buffer) {
    static auto function = SystemExport<decltype(&TdhGetWppProperty)>("TdhGetWppProperty");
    return function ? function(Handle, EventRecord, PropertyName, BufferSize, Buffer) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhGetWppMessage(TDH_HANDLE Handle, PEVENT_RECORD EventRecord, PULONG BufferSize, PBYTE Buffer) {
    static auto function = SystemExport<decltype(&TdhGetWppMessage)>("TdhGetWppMessage");
    return function ? function(Handle, EventRecord, BufferSize, Buffer) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhCloseDecodingHandle(TDH_HANDLE Handle) {
    static auto function = SystemExport<decltype(&TdhCloseDecodingHandle)>("TdhCloseDecodingHandle");
    return function ? function(Handle) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhLoadManifestFromBinary(PWSTR BinaryPath) {
    static auto function = SystemExport<decltype(&TdhLoadManifestFromBinary)>("TdhLoadManifestFromBinary");
    return function ? function(BinaryPath) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhEnumerateManifestProviderEvents(LPGUID ProviderGuid, PPROVIDER_EVENT_INFO Buffer, ULONG* BufferSize) {
    static auto function = SystemExport<decltype(&TdhEnumerateManifestProviderEvents)>("TdhEnumerateManifestProviderEvents");
    return function ? function(ProviderGuid, Buffer, BufferSize) : ERROR_PROC_NOT_FOUND;
}
extern "C" TDHSTATUS WINAPI Shim_TdhGetManifestEventInformation(LPGUID ProviderGuid, PEVENT_DESCRIPTOR EventDescriptor, PTRACE_EVENT_INFO Buffer, ULONG* BufferSize) {
    static auto function = SystemExport<decltype(&TdhGetManifestEventInformation)>("TdhGetManifestEventInformation");
    return function ? function(ProviderGuid, EventDescriptor, Buffer, BufferSize) : ERROR_PROC_NOT_FOUND;
}
