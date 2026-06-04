extern "C" void ManualMapEntry(void* arg) {
    volatile void* sink = arg;
    (void)sink;
}
