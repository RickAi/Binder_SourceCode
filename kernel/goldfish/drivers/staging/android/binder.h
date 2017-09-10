/*
 * Copyright (C) 2008 Google, Inc.
 *
 * Based on, but no longer compatible with, the original
 * OpenBinder.org binder driver interface, which is:
 *
 * Copyright (c) 2005 Palmsource, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#ifndef _LINUX_BINDER_H
#define _LINUX_BINDER_H

#include <linux/ioctl.h>

#define B_PACK_CHARS(c1, c2, c3, c4) \
	((((c1)<<24)) | (((c2)<<16)) | (((c3)<<8)) | (c4))
#define B_TYPE_LARGE 0x85

enum {
	// 用来描述一个Binder实体对象
	// 描述强类型
	BINDER_TYPE_BINDER	= B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE),
	// 用来描述一个Binder引用对象
	// 描述弱类型
	BINDER_TYPE_WEAK_BINDER	= B_PACK_CHARS('w', 'b', '*', B_TYPE_LARGE),
	// 描述强类型
	BINDER_TYPE_HANDLE	= B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE),
	// 描述弱类型
	BINDER_TYPE_WEAK_HANDLE	= B_PACK_CHARS('w', 'h', '*', B_TYPE_LARGE),
	// 描述一个文件描述符
	BINDER_TYPE_FD		= B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE),
};

enum {
	FLAT_BINDER_FLAG_PRIORITY_MASK = 0xff,
	FLAT_BINDER_FLAG_ACCEPTS_FDS = 0x100,
};

/*
 * This is the flattened representation of a Binder object for transfer
 * between processes.  The 'offsets' supplied as part of a binder transaction
 * contains offsets into the data where these structures occur.  The Binder
 * driver takes care of re-writing the structure type and data as it moves
 * between processes.
 */
// 可以用来描述Binder实体对象，Binder引用对象，文件描述符
// 通过type来区别
struct flat_binder_object {
	/* 8 bytes for large_flat_header. */
	unsigned long		type;
	// 标志值，只有结构体flat_binder_object描述的是一个Binder实体对象时，它才有意义
	unsigned long		flags;

	/* 8 bytes of data. */
	// 如果描述的是一个Binder实体对象时，
	// 那么使用binder来指向该Binder实体对象对应的Service组件内部的一个弱引用对象的地址
	// 并且使用cookie来指向该Service组件的地址
	// 如果描述的是Binder引用对象时，那么使用handle来描述该Binder引用对象的句柄值
	union {
		void		*binder;	/* local object */
		signed long	handle;		/* remote object */
	};

	/* extra data associated with local object */
	void			*cookie;
};

/*
 * On 64-bit platforms where user code may run in 32-bits the driver must
 * translate the buffer (and local binder) addresses apropriately.
 */

// 用来描述进程间通信过程中所传输的数据
// 包括输入数据和输出数据
// [write_buffer和read_buffer数据都是一个数组，数组的每一个元素都是由一个通信协议代码及其通信数据组成的
// 协议代码又分两种类型
// 一种是在输入缓冲区write_buffer中使用的，称为命令协议代码
// 另一种是在输出缓冲区read_buffer中使用，又称为返回协议代码]
struct binder_write_read {
	// 输入数据，从用户空间传输到Binder驱动程序的数据
	signed long	write_size;	/* bytes to write */
	// 用来描述Binder驱动程序从缓冲区write_buffer中处理了多少个字节的数据
	signed long	write_consumed;	/* bytes consumed by driver */
	// 大小由成员变量write_size来指定，单位是字节
	unsigned long	write_buffer;
	// 输出数据，从驱动返回给用户空间的数据，也是进程间通信的结果数据
	signed long	read_size;	/* bytes to read */
	signed long	read_consumed;	/* bytes consumed by driver */
	// 指向一个用户空间缓冲区的地址，里面保存的内容即为Binder驱动程序返回给用户空间的进程间通信结果数据
	unsigned long	read_buffer;
};

/* Use with BINDER_VERSION, driver fills in fields. */
struct binder_version {
	/* driver protocol version -- increment with incompatible change */
	signed long	protocol_version;
};

/* This is the current protocol version. */
#define BINDER_CURRENT_PROTOCOL_VERSION 7

#define BINDER_WRITE_READ   		_IOWR('b', 1, struct binder_write_read)
#define	BINDER_SET_IDLE_TIMEOUT		_IOW('b', 3, int64_t)
#define	BINDER_SET_MAX_THREADS		_IOW('b', 5, size_t)
#define	BINDER_SET_IDLE_PRIORITY	_IOW('b', 6, int)
#define	BINDER_SET_CONTEXT_MGR		_IOW('b', 7, int)
#define	BINDER_THREAD_EXIT		_IOW('b', 8, int)
#define BINDER_VERSION			_IOWR('b', 9, struct binder_version)

/*
 * NOTE: Two special error codes you should check for when calling
 * in to the driver are:
 *
 * EINTR -- The operation has been interupted.  This should be
 * handled by retrying the ioctl() until a different error code
 * is returned.
 *
 * ECONNREFUSED -- The driver is no longer accepting operations
 * from your process.  That is, the process is being destroyed.
 * You should handle this by exiting from your process.  Note
 * that once this error code is returned, all further calls to
 * the driver from any thread will return this same code.
 */

enum transaction_flags {
	// 是否是异步通信
	TF_ONE_WAY	= 0x01,	/* this is a one-way call: async, no return */
	TF_ROOT_OBJECT	= 0x04,	/* contents are the component's root object */
	// 成员变量data所描述的数据缓冲区的内容是否是一个4字节的状态码
	TF_STATUS_CODE	= 0x08,	/* contents are a 32-bit status code */
	// 源进程是否允许目标进程返回的结果数据中包含文件描述符
	TF_ACCEPT_FDS	= 0x10,	/* allow replies with file descriptors */
};

// 用来描述进程间通信过程中所传输的数据
struct binder_transaction_data {
	/* The first two are only used for bcTRANSACTION and brTRANSACTION,
	 * identifying the target and contents of the transaction.
	 */
	// 用来描述一个目标Binder实体对象或者目标Binder引用对象
	// 如果是实体对象，那么成员变量ptr就指向该实体对象对应的Service组件内部的弱引用计数对象的地址
	// 如果是引用对象，那么成员变量handle就指向该Binder引用对象的句柄值
	union {
		size_t	handle;	/* target descriptor of command transaction */
		void	*ptr;	/* target descriptor of return transaction */
	} target;
	// 由应用程序进程指定的额外参数
	// 当Binder驱动使用返回命令协议BR_TRANSACTION向一个Server进程发出一个进程间通信请求时
	// 这个变量才有意义，它指向的是目标Service组件的地址
	void		*cookie;	/* target object cookie */
	// 由执行进程间同学你的两个进程互相约定好的一个代码
	// 驱动不关心含义
	unsigned int	code;		/* transaction command */

	/* General information about the transaction. */
	unsigned int	flags;
	// 发起进程间通信的请求进程的pid和uid
	pid_t		sender_pid;
	uid_t		sender_euid;
	// 用来描述一个通信数据缓冲区以及一个偏移数组的大小
	size_t		data_size;	/* number of bytes of data */
	size_t		offsets_size;	/* number of bytes of offsets */

	/* If this transaction is inline, the data immediately
	 * follows here; otherwise, it ends with a pointer to
	 * the data buffer.
	 */
	// 一个联合体
	// 指向一个通信数据缓冲区
	// 当通信数据较小时，使用联合体中的静态分配的数组buf来传输数据
	// 当通信数据较大时，使用一块动态分配的缓冲区来传输数据
	// 这块数据缓冲区通过一个包含两个指针的结构体来描述
	// 结构体ptr的成员变量buffer指向一个数据缓冲区，用来保存通信数据，大小根据变量data_size来指定
	// 当数据缓冲区中有Binder对象时，紧跟着这个数据缓冲区后面就会有一个偏移数组offsets
	// 用来描述缓冲区中每一个Binder对象的位置
	// 有了偏移数组，驱动可以正确地维护其内部的Binder实体对象和Binder引用对象的引用计数
	union {
		struct {
			/* transaction data */
			const void	*buffer;
			/* offsets from buffer to flat_binder_object structs */
			const void	*offsets;
		} ptr;
		uint8_t	buf[8];
	} data;
};

// 用来描述一个Binder实体对象或者一个Service组件的死亡通知
// 如果用来描述Binder实体对象，ptr、cookie含义等同于前面所介绍的结构体binder_node的ptr和cookie
// 如果用来描述死亡接受通知时，ptr指向一个Binder引用对象的句柄值，而成员变量指向的是一个用来接受死亡通知的对象地址
struct binder_ptr_cookie {
	void *ptr;
	void *cookie;
};

struct binder_pri_desc {
	int priority;
	int desc;
};

struct binder_pri_ptr_cookie {
	int priority;
	void *ptr;
	void *cookie;
};

enum BinderDriverReturnProtocol {
	// 驱动处理应用数据发出的请求中时，如果发生了异常，就会返回这个代码通知应用进程
	BR_ERROR = _IOR('r', 0, int),
	/*
	 * int: error code
	 */

	// 驱动处理请求成功，返回代码通知应用进程
	BR_OK = _IO('r', 1),
	/* No parameters! */

	// 当Client进程向Server进程发出进程间通信请求时，Binder驱动使用代码来
	// 通知Server进程发出进程间通信的请求
	BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),
	// 当Server进程处理完成该进程间通信请求之后，Binder驱动就会使用这个代码将
	// 进程间通信请求结果数据返回给Client进程
	BR_REPLY = _IOR('r', 3, struct binder_transaction_data),
	/*
	 * binder_transaction_data: the received command.
	 */

	BR_ACQUIRE_RESULT = _IOR('r', 4, int),
	/*
	 * not currently supported
	 * int: 0 if the last bcATTEMPT_ACQUIRE was not successful.
	 * Else the remote object has acquired a primary reference.
	 */

	BR_DEAD_REPLY = _IO('r', 5),
	/*
	 * The target of the last transaction (either a bcTRANSACTION or
	 * a bcATTEMPT_ACQUIRE) is no longer with us.  No parameters.
	 */

	// 返回该代码给应用进程，告知该协议代码已经被接受，正在发给目标进程或者目标线程处理
	BR_TRANSACTION_COMPLETE = _IO('r', 6),
	/*
	 * No parameters... always refers to the last transaction requested
	 * (including replies).  Note that this will be sent even for
	 * asynchronous transactions.
	 */

	// 用来增加和减少一个Service组件的强引用和弱引用计数
	BR_INCREFS = _IOR('r', 7, struct binder_ptr_cookie),
	BR_ACQUIRE = _IOR('r', 8, struct binder_ptr_cookie),
	BR_RELEASE = _IOR('r', 9, struct binder_ptr_cookie),
	BR_DECREFS = _IOR('r', 10, struct binder_ptr_cookie),
	/*
	 * void *:	ptr to binder
	 * void *: cookie for binder
	 */

	BR_ATTEMPT_ACQUIRE = _IOR('r', 11, struct binder_pri_ptr_cookie),
	/*
	 * not currently supported
	 * int:	priority
	 * void *: ptr to binder
	 * void *: cookie for binder
	 */

	BR_NOOP = _IO('r', 12),
	/*
	 * No parameters.  Do nothing and examine the next command.  It exists
	 * primarily so that we can replace it with a BR_SPAWN_LOOPER command.
	 */

	// 驱动发现没有足够的空闲Binder线程来处理进程间通信请求
	// 发送这个代码来通知该进程增加一个新的线程到Binder线程池中
	BR_SPAWN_LOOPER = _IO('r', 13),
	/*
	 * No parameters.  The driver has determined that a process has no
	 * threads waiting to service incomming transactions.  When a process
	 * receives this command, it must spawn a new service thread and
	 * register it via bcENTER_LOOPER.
	 */

	BR_FINISHED = _IO('r', 14),
	/*
	 * not currently supported
	 * stop threadpool thread
	 */

	// 指向一个接受Service组件死亡通知的对象的地址
	// 当Bindr驱动检测到一个Service组件死亡事件时，使用这个代码来通知相应的Client进程
	BR_DEAD_BINDER = _IOR('r', 15, void *),
	/*
	 * void *: cookie
	 */

	// 当Client通知驱动注销死亡通知时，驱动使用这个代码表示注销操作已经完成
	BR_CLEAR_DEATH_NOTIFICATION_DONE = _IOR('r', 16, void *),
	/*
	 * void *: cookie
	 */

	// 当驱动处理一个进程发出的BC_TRANSACTION命令协议时
	// 如果出现了异常，它会使用这个代码来通知源进程
	BR_FAILED_REPLY = _IO('r', 17),
	/*
	 * The the last transaction (either a bcTRANSACTION or
	 * a bcATTEMPT_ACQUIRE) failed (e.g. out of memory).  No parameters.
	 */
};

enum BinderDriverCommandProtocol {
	// 当一个进程请求另外一个进程执行某一个操作时，源进程就使用命令这个协议来请求Binder驱动程序
	// 将通信数据传递到目标进程中
	BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
	// 当目标进程处理完成源代码所请求的操作之后，就使用命令这个协议来请求驱动将结果传递给源进程
	BC_REPLY = _IOW('c', 1, struct binder_transaction_data),
	/*
	 * binder_transaction_data: the sent command.
	 */

	BC_ACQUIRE_RESULT = _IOW('c', 2, int),
	/*
	 * not currently supported
	 * int:  0 if the last BR_ATTEMPT_ACQUIRE was not successful.
	 * Else you have acquired a primary reference on the object.
	 */
	// 指向了在Binder驱动程序内部所分配的一块内核缓冲区
	// Binder驱动使用这个缓冲区将源进程的通信数据传递到目标进程
	// 当目标进程处理完成源进程的通信请求后，会使用这个协议来通知驱动释放这个内核缓冲区
	BC_FREE_BUFFER = _IOW('c', 3, int),
	/*
	 * void *: ptr to transaction data received on a read
	 */
	// 驱动第一次增加一个Binder实体对象的强引用计数或者弱引用计数时
	// 就会使用这个协议来请求对应的Server进程增加对应的Service组件的强引用弱引用计数
	BC_INCREFS = _IOW('c', 4, int),
	BC_ACQUIRE = _IOW('c', 5, int),
	BC_RELEASE = _IOW('c', 6, int),
	BC_DECREFS = _IOW('c', 7, int),
	/*
	 * int:	descriptor
	 */
	// 当Server进程处理完成这两个请求之后，就会分别使用命令协议代码将结果返回给驱动
	BC_INCREFS_DONE = _IOW('c', 8, struct binder_ptr_cookie),
	BC_ACQUIRE_DONE = _IOW('c', 9, struct binder_ptr_cookie),
	/*
	 * void *: ptr to binder
	 * void *: cookie for binder
	 */

	BC_ATTEMPT_ACQUIRE = _IOW('c', 10, struct binder_pri_desc),
	/*
	 * not currently supported
	 * int: priority
	 * int: descriptor
	 */
	// 当Binder驱动程序主动请求进程注册一个新的线程到它的Binder线程池中来
	// 处理进程间通信请求之后，新创建的线程就会使用这个命令协议代码
	// 通知驱动已经准备就绪了
	BC_REGISTER_LOOPER = _IO('c', 11),
	/*
	 * No parameters.
	 * Register a spawned looper thread with the device.
	 */
	// 当一个线程将自己注册到Binder驱动程序之后，它接着就会使用这个命令协议代码
	// 通知驱动，当前线程已经准备就绪处理进程间的通信请求了
	BC_ENTER_LOOPER = _IO('c', 12),
	// 当线程要退出时，使用这个协议代码从驱动中注销，不会再接受到进程间的通信请求了
	BC_EXIT_LOOPER = _IO('c', 13),
	/*
	 * No parameters.
	 * These two commands are sent as an application-level thread
	 * enters and exits the binder loop, respectively.  They are
	 * used so the binder can have an accurate count of the number
	 * of looping threads it has available.
	 */
	// 如果一个进程希望获得它所引用的Service组件的死亡接受通知，那么它就使用这个敏玲向
	// 驱动注册一个死亡接受通知
	BC_REQUEST_DEATH_NOTIFICATION = _IOW('c', 14, struct binder_ptr_cookie),
	/*
	 * void *: ptr to binder
	 * void *: cookie
	 */
	// 如果进程注销一个死亡通知，使用这个协议代码发送给驱动来进行请求
	BC_CLEAR_DEATH_NOTIFICATION = _IOW('c', 15, struct binder_ptr_cookie),
	/*
	 * void *: ptr to binder
	 * void *: cookie
	 */
	// 指向了死亡接受通知结构体binder_ref_death
	// 当一个进程获得一个Service组件的死亡通知时，它就会使用这个命令协议通知驱动
	// 当前已经处理完成该Service组件的死亡通知
	BC_DEAD_BINDER_DONE = _IOW('c', 16, void *),
	/*
	 * void *: cookie
	 */
};

#endif /* _LINUX_BINDER_H */

