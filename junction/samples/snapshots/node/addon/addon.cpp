#include <v8.h>
#include <node.h>

using namespace v8;

void Freeze(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  isolate->Freeze();
}


void Unfreeze(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  isolate->Unfreeze();
}

void Init(Local<Object> exports, Local<v8::Value>, void *) {
    NODE_SET_METHOD(exports, "freeze", Freeze);
    NODE_SET_METHOD(exports, "unfreeze", Unfreeze);
}

NODE_MODULE(NODE_GYP_MODULE_NAME, Init)
