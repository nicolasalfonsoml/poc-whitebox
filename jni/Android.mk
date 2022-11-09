LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_LDLIBS := -llog
LOCAL_MODULE := whitebox
LOCAL_SRC_FILES := com_example_whitboxwithjni_WhiteBox.cpp

include $(BUILD_SHARED_LIBRARY)