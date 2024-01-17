#include <node.h>
#include <unistd.h>

namespace snapshot {

  using namespace v8;

  constexpr unsigned long SYS_snapshot = 455;
  
  void Snapshot(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate *isolate = args.GetIsolate();
    
    if (args.Length() < 1 || !args[0]->IsString()) {
      isolate->ThrowException(
        v8::Exception::TypeError(
	  v8::String::NewFromUtf8(isolate, "elf path must be a string").ToLocalChecked()
      ));
    }

    if (args.Length() < 2 || !args[1]->IsString()) {
      isolate->ThrowException(
        v8::Exception::TypeError(
	  v8::String::NewFromUtf8(isolate, "metadata path must be a string").ToLocalChecked()
	));
    }

    String::Utf8Value elf(isolate, args[0]);
    char const* elf_filename = *elf;

    String::Utf8Value metadata(isolate, args[1]);
    char const* metadata_filename = *metadata;

    long ret;
    asm("movq %1, %%rax;"
	"movq %2, %%rdi;"
	"movq %3, %%rsi;"
	"syscall;"
	"movq %%rax, %0;"
	: "=r"(ret)
	: "r"(SYS_snapshot), "r"(elf_filename), "r"(metadata_filename)
	: "%rax", "%rdi", "%rsi");
      
    args.GetReturnValue().Set(Number::New(isolate, ret));
  }
  void Init(v8::Local<v8::Object> exports) {
    NODE_SET_METHOD(exports, "snapshot", Snapshot);
  }

  NODE_MODULE(NODE_GYP_MODULE_NAME, Init);
} // namespace snapshot
