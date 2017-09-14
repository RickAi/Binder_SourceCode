#define LOG_TAG "FregServer"

#include <stdlib.h>
#include <fcntl.h>

#include <utils/Log.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>

#include "../common/IFregService.h"

#define FREG_DEVICE_NAME "/dev/freg"

// server模块的源代码
// 继承自BnFregService,实现了IFregService接口
class FregService : public BnFregService
{
public:
	// 在析造函数中会调用open来打开设备文件
	FregService()
	{
		fd = open(FREG_DEVICE_NAME, O_RDWR);
		if(fd == -1) {
			LOGE("Failed to open device %s.\n", FREG_DEVICE_NAME);
		}
	}

	virtual ~FregService()
	{
		if(fd != -1) {
			close(fd);
		}
	}

public:
	static void instantiate()
	{
		defaultServiceManager()->addService(String16(FREG_SERVICE), new FregService());
	}

	int32_t getVal()
	{
		int32_t val = 0;

		if(fd != -1) {
			read(fd, &val, sizeof(val));
		}

		return val;
	}

	void setVal(int32_t val)
        {
                if(fd != -1) {
                        write(fd, &val, sizeof(val));
                }
        }

private:
	int fd;
};

int main(int argc, char** argv)
{
	// 首先调用静态成员函数将FregService组件注册到Service Manager中
	FregService::instantiate();

	// 启动一个Binder线程池
	ProcessState::self()->startThreadPool();
	// 调用主线程的IPCThreadState对象的成员函数添加到进程的Binder线程池中，用来处理来自Client进程通信
	IPCThreadState::self()->joinThreadPool();

	return 0;
}
