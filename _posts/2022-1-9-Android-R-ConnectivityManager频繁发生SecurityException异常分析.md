
在Android-R上 ，APP在调用ConnectivityManager的多个methods有概率性的发生SecurityException异常，异常的信息都是相似的 “Package android does not belong to xxx”。
从堆栈看，异常是在framework中的ConnectivityService抛出的，ConnectivityService在检查调用方的权限时候主动抛出的异常。

# 异常信息

当APP调用getNetworkCapabilities方法的时候，发生的SecurityException异常：
```
 FATAL EXCEPTION: CronetInit
 java.lang.SecurityException: Package android does not belong to 10131
 	at android.os.Parcel.createExceptionOrNull(Parcel.java:2373)
 	at android.os.Parcel.createException(Parcel.java:2357)
 	at android.os.Parcel.readException(Parcel.java:2340)
 	at android.os.Parcel.readException(Parcel.java:2282)
 	at android.net.IConnectivityManager$Stub$Proxy.getNetworkCapabilities(IConnectivityManager.java:2456)
 	at android.net.ConnectivityManager.getNetworkCapabilities(ConnectivityManager.java:1419)
 	at aquo.c(PG:1)
 	at org.chromium.net.NetworkChangeNotifierAutoDetect.getAllNetworksFiltered(PG:4)
 	at org.chromium.net.NetworkChangeNotifierAutoDetect.access$100(PG:1)
 	at org.chromium.net.NetworkChangeNotifierAutoDetect.register(PG:5)
 	at org.chromium.net.NetworkChangeNotifierAutoDetect$RegistrationPolicy.register(PG:1)
 	at org.chromium.net.RegistrationPolicyAlwaysRegister.init(PG:2)
 	at org.chromium.net.NetworkChangeNotifierAutoDetect.<init>(PG:16)
 	at org.chromium.net.NetworkChangeNotifier.setAutoDetectConnectivityStateInternal(PG:1)
 	at org.chromium.net.NetworkChangeNotifier.registerToReceiveNotificationsAlways(PG:1)
 	at org.chromium.net.impl.CronetLibraryLoader.b(PG:2)
 	at aqvy.run(PG:1)
 	at android.os.Handler.handleCallback(Handler.java:938)
 	at android.os.Handler.dispatchMessage(Handler.java:99)
 	at android.os.Looper.loop(Looper.java:268)
 	at android.os.HandlerThread.run(HandlerThread.java:67)
 Caused by: android.os.RemoteException: Remote stack trace:
 	at android.app.AppOpsManager.checkPackage(AppOpsManager.java:7757)
 	at com.android.server.ConnectivityService.getNetworkCapabilities(ConnectivityService.java:1741)
 	at android.net.IConnectivityManager$Stub.onTransact(IConnectivityManager.java:978)
 	at android.os.Binder.execTransactInternal(Binder.java:1169)
 	at android.os.Binder.execTransact(Binder.java:1126)
```

当APP调用requestNetwork方法的时候，发生的SecurityException异常：
```
java.lang.SecurityException: Package android does not belong to 10154
	at android.os.Parcel.createExceptionOrNull(Parcel.java:2373)
	at android.os.Parcel.createException(Parcel.java:2357)
	at android.os.Parcel.readException(Parcel.java:2340)
	at android.os.Parcel.readException(Parcel.java:2282)
	at android.net.IConnectivityManager$Stub$Proxy.requestNetwork(IConnectivityManager.java:3503)
	at android.net.ConnectivityManager.sendRequestForNetwork(ConnectivityManager.java:3756)
	at android.net.ConnectivityManager.registerDefaultNetworkCallback(ConnectivityManager.java:4259)
	at X.0HG.AVk(:90244)
	at X.0H6.handleMessage(:89902)
	at android.os.Handler.dispatchMessage(Handler.java:106)
	at android.os.Looper.loop(Looper.java:268)
	at android.app.ActivityThread.main(ActivityThread.java:7882)
	at java.lang.reflect.Method.invoke(Native Method)
	at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:627)
	at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:997)
Caused by: android.os.RemoteException: Remote stack trace:
	at android.app.AppOpsManager.checkPackage(AppOpsManager.java:7757)
	at com.android.server.ConnectivityService.ensureSufficientPermissionsForRequest(ConnectivityService.java:5616)
	at com.android.server.ConnectivityService.requestNetwork(ConnectivityService.java:5711)
	at android.net.IConnectivityManager$Stub.onTransact(IConnectivityManager.java:1570)
	at android.os.Binder.execTransactInternal(Binder.java:1169)
```


# 代码分析
首先查看异常发生对应的代码
```
ConnectivityService.getNetworkCapabilities(Network, String)  (com.android.server)
    public NetworkCapabilities getNetworkCapabilities(Network network, String callingPackageName) {
        // 检查调用者的权限
        mAppOpsManager.checkPackage(Binder.getCallingUid(), callingPackageName);
        ...
    }
```

从异常信息可以看到，getCallingUid()为APP自身的uid，此值正常，但callingPackageName为android，并非APP自身的name。
```
AppOpsManager.checkPackage(int, String)  (android.app)
    public void checkPackage(int uid, @NonNull String packageName) {
        try {
            if (mService.checkPackage(uid, packageName) != MODE_ALLOWED) {
                throw new SecurityException(
                        "Package " + packageName + " does not belong to " + uid);
            }
        } catch (RemoteException e) {
            throw e.rethrowFromSystemServer();
        }
    }
```

问题出在APP在调用自身的mContext.getOpPackageName出现了问题，异常时候获取到的为“android”
```
ConnectivityManager.getNetworkCapabilities(Network)  (android.net)
    public NetworkCapabilities getNetworkCapabilities(@Nullable Network network) {
        try {
            return mService.getNetworkCapabilities(network, mContext.getOpPackageName());
        }
}
```

查看context对应获取packageName的实现: 
依次寻找的变量为 mOpPackageName -> mBasePackageName  -> mPackageName -> "android" 
最后默认为android，即代表system自己的context。
```
    public String getOpPackageName() {
        return mOpPackageName != null ? mOpPackageName : getBasePackageName();
    }
    public String getBasePackageName() {
        return mBasePackageName != null ? mBasePackageName : getPackageName();
    }
    public String getPackageName() {
        if (mPackageInfo != null) {
            return mPackageInfo.getPackageName();
        }
        // No mPackageInfo means this is a Context for the system itself,
        // and this here is its name.
        return "android";
    }
    public String getPackageName() {
        return mPackageName;
    }
```

对于mOpPackageName，在context初始化的时候就会获取当前的packageName、mBasePackageName。
每个APP都会有对应的packageName，肯定不会为空。
```
    private ContextImpl(@Nullable ContextImpl container, ... @Nullable String overrideOpPackageName) {
            mBasePackageName = packageInfo.mPackageName;
            ApplicationInfo ainfo = packageInfo.getApplicationInfo();
            if (ainfo.uid == Process.SYSTEM_UID && ainfo.uid != Process.myUid()) {
                // Special case: system components allow themselves to be loaded in to other
                // processes.  For purposes of app ops, we must then consider the context as
                // belonging to the package of this process, not the system itself, otherwise
                // the package+uid verifications in app ops will fail.
                opPackageName = ActivityThread.currentPackageName();
            } else {
                opPackageName = mBasePackageName;
            }
        }

        mOpPackageName = overrideOpPackageName != null ? overrideOpPackageName : opPackageName;
    }
```

对应system service的Context创建 显示其context的packageName确实为"android" 。
```
    //frameworks/base/core/java/android/app/ActivityThread.java
    public ContextImpl getSystemContext() {
        synchronized (this) {
            if (mSystemContext == null) {
                mSystemContext = ContextImpl.createSystemContext(this);
            }
            return mSystemContext;
        }
    }
    //frameworks/base/core/java/android/app/ContextImpl.java
    static ContextImpl createSystemContext(ActivityThread mainThread) {
        LoadedApk packageInfo = new LoadedApk(mainThread);
        return context;
    }
    //frameworks/base/core/java/android/app/LoadedApk.java
    /**
     * Create information about the system package.
     * Must call {@link #installSystemApplicationInfo} later.
     */
    LoadedApk(ActivityThread activityThread) {
        mActivityThread = activityThread;
        mApplicationInfo = new ApplicationInfo();
        mApplicationInfo.packageName = "android";
        mPackageName = "android";
    }
```

结合以上信息以及更多的埋点可以确认 ，此时APP的ConnectivityManager的mContext是一个system类型的context。

接下来需要进一步确认为何ConnectivityManager会拿到system的context，所以就需要通过其初始化的流程查找原因:

##ConnectivityManager的mContext初始化流程如下：

mContext唯一初始化的地方就是ConnectivityManager的类对象构造的时候，在其构造方法中会存储传入的context。
```
    public ConnectivityManager(Context context, IConnectivityManager service) {
        mContext = Preconditions.checkNotNull(context, "missing context");
        mService = Preconditions.checkNotNull(service, "missing IConnectivityManager");
        mTetheringManager = (TetheringManager) mContext.getSystemService(Context.TETHERING_SERVICE);
        sInstance = this;
    }
```

ConnectivityManager的初始化使用的是 StaticApplicationContextServiceFetcher 类。
```
// frameworks/base/core/java/android/app/SystemServiceRegistry.java
    static {
        ...
        registerService(Context.CONNECTIVITY_SERVICE, ConnectivityManager.class,
                new StaticApplicationContextServiceFetcher<ConnectivityManager>() {
            @Override
            public ConnectivityManager createService(Context context) throws ServiceNotFoundException {
                IBinder b = ServiceManager.getServiceOrThrow(Context.CONNECTIVITY_SERVICE);
                IConnectivityManager service = IConnectivityManager.Stub.asInterface(b);
                return new ConnectivityManager(context, service);
            }});
        ...
    }
```

APP在使用CONNECTIVITY服务时，通过调用 context.getSystemService(Context.CONNECTIVITY_SERVICE)方法来拿到与系统服务通信的接口对象类。
这里 StaticApplicationContextServiceFetcher 类有个mCachedInstance变量，用于存储ConnectivityManager的实例。所以，一个进程在第一个使用ConnectivityManager的时候就会传入当前的context。之后再次使用ConnectivityManager则直接拿到这个已经初始化过的mCachedInstance。
```
    static abstract class StaticApplicationContextServiceFetcher<T> implements ServiceFetcher<T> {
        private T mCachedInstance;
        @Override
        public final T getService(ContextImpl ctx) {
            synchronized (StaticApplicationContextServiceFetcher.this) {
                if (mCachedInstance == null) {
                    Context appContext = ctx.getApplicationContext();
                    try {
                        mCachedInstance = createService(appContext != null ? appContext : ctx);
                    } ...
                }
                return mCachedInstance;
        public abstract T createService(Context applicationContext) throws ServiceNotFoundException;
    }
```

问题发生在第一次使用ConnectivityManager时候传入的context，通过跟过的埋点以及debug可以确定，问题发生的时候）一个APP进程最早的一次使用是在下面的方法中 
```
MainHandler in ActivityManagerService.handleMessage(Message)  (com.android.server.am)
ProcessList.setAllHttpProxy()  (com.android.server.am)
ApplicationThread in ActivityThread.updateHttpProxy()  (android.app)
ActivityThread.updateHttpProxy(Context)  (android.app)
    public static void updateHttpProxy(@NonNull Context context) {
        final ConnectivityManager cm = ConnectivityManager.from(context);
        Proxy.setHttpProxySystemProperty(cm.getDefaultProxy());
    }
```

updateHttpProxy(Context) 使用的是 ActivityThread.updateHttpProxy()无入参的这个方法传入的context：
```
        public void updateHttpProxy() {
            ActivityThread.updateHttpProxy(
                    getApplication() != null ? getApplication() : getSystemContext());
        }
```
也就是说，在有些情况下，getApplication() 返回为空，导致直接传入了getSystemContext。


## 接下来则需要确认，是什么原因会导致getApplication返回空呢？

首先看到getApplication返回的是ActivityThread的mInitialApplication，后者最初是在handleBindApplication中被初始化的。

### 2.1:APP进程启动，应用进程attach到 AMS ，然后再会返回到APP的主线程
```
ActivityThread.main(String[])  (android.app)
ActivityThread.attach(boolean, long)  (android.app)
ActivityManagerService.attachApplication(IApplicationThread, long)  (com.android.server.am)
ActivityManagerService.attachApplicationLocked(IApplicationThread, int, int, long)(2 usages)  (com.android.server.am)
ApplicationThread in ActivityThread.bindApplication(String, ApplicationInfo, ProviderInfoList, ComponentName, ProfilerInfo, Bundle, IInstrumentationWatcher, ...)  (android.app) {
  ...
  sendMessage(H.BIND_APPLICATION, data);
  ...
}
```

```
public void handleMessage(Message msg) {
                case BIND_APPLICATION:
                    AppBindData data = (AppBindData)msg.obj;
                    handleBindApplication(data);

private void handleBindApplication(AppBindData data) {
...
    Application app;
        try {
            // If the app is being launched for full backup or restore, bring it up in
            // a restricted environment with the base application class.
            app = data.info.makeApplication(data.restrictedBackupMode, null);

            mInitialApplication = app;
            try {
                mInstrumentation.callApplicationOnCreate(app); // 调用到APP的application 中的onCreate方法
            }

mInitialApplication在进程启动后，attach到ams后就被初始化了，整个过程都是在main主线程上进行的。
```

### 2.2：updateHttpProxy()
一个Binder接口，提供其他进程调用
```
oneway interface IApplicationThread {
    void updateHttpProxy();
}
```

可以看到，当系统代理有更新后会广播代理更新的代理，然后AMS会遍历mLruProcesses中所有的进程，通过updateHttpProxy方法通知相关进程有代理的更新。

```
    /**
     * Sends the system broadcast informing apps about a new proxy configuration.
     *
     * Confusingly this method also sets the PAC file URL. TODO : separate this, it has nothing
     * to do in a "sendProxyBroadcast" method.
     */
    public void sendProxyBroadcast() {
        Intent intent = new Intent(Proxy.PROXY_CHANGE_ACTION);
        try {
            mContext.sendStickyBroadcastAsUser(intent, UserHandle.ALL);
        }
    }

    final class MainHandler extends Handler {
        public MainHandler(Looper looper) {
            super(looper, null, true);
        }

        @Override
        public void handleMessage(Message msg) {
            case UPDATE_HTTP_PROXY_MSG: {
                mProcessList.setAllHttpProxy();
            } break;
    }

    void setAllHttpProxy() {
        // Update the HTTP proxy for each application thread.
        synchronized (mService) {
            for (int i = mLruProcesses.size() - 1 ; i >= 0 ; i--) {
                ProcessRecord r = mLruProcesses.get(i);
                // Don't dispatch to isolated processes as they can't access ConnectivityManager and
                // don't have network privileges anyway. Exclude system server and update it
                // separately outside the AMS lock, to avoid deadlock with Connectivity Service.
                if (r.pid != ActivityManagerService.MY_PID && r.thread != null && !r.isolated) {
                    try {
                        r.thread.updateHttpProxy();
                    } 
        ....
    }
```

## 小结
当代理更新的方法在binder线程调用的时候早于主线程的初始化mInitialApplication的情况下，问题就出现。那么当问题的root cause找到之后，就可以着手解决问题了。

# 解决方案

问题的root cause就是访问时序的问题，需要确保mInitialApplication被初始化后才能使用。另外，因为涉及到多个线程，这里还需要考虑到线程安全问题。通常解决线程安全的问题，一个基本的思路就是加锁。

```
diff --git a/core/java/android/app/ActivityThread.java b/core/java/android/app/ActivityThread.java
index 3915abe..dbaf275 100644
--- a/core/java/android/app/ActivityThread.java
+++ b/core/java/android/app/ActivityThread.java
@@ -369,11 +369,12 @@ public final class ActivityThread extends ClientTransactionHandler
     @UnsupportedAppUsage(trackingBug = 176961850, maxTargetSdk = Build.VERSION_CODES.R,
             publicAlternatives = "Use {@code Context#getResources()#getConfiguration()} instead.")
     Configuration mConfiguration;
+    @GuardedBy("this")
+    private boolean mUpdateHttpProxyOnBind = false;
     @UnsupportedAppUsage
     Application mInitialApplication;
     @UnsupportedAppUsage
     /**
      * Bookkeeping of instantiated backup agents indexed first by user id, then by package name.
      * Indexing by user id supports parallel backups across users on system packages as they run in
@@ -1187,8 +1188,18 @@ public final class ActivityThread extends ClientTransactionHandler
         }
 
         public void updateHttpProxy() {
-            ActivityThread.updateHttpProxy(
-                    getApplication() != null ? getApplication() : getSystemContext());
+            final Application app;
+            synchronized (ActivityThread.this) {
+                app = getApplication();
+                if (null == app) {
+                    // The app is not bound yet. Make a note to update the HTTP proxy when the
+                    // app is bound.
+                    mUpdateHttpProxyOnBind = true;
+                    return;
+                }
+            }
+            // App is present, update the proxy inline.
+            ActivityThread.updateHttpProxy(app);
         }
 
         public void processInBackground() {
@@ -6685,6 +6696,15 @@ public final class ActivityThread extends ClientTransactionHandler
             sendMessage(H.SET_CONTENT_CAPTURE_OPTIONS_CALLBACK, data.appInfo.packageName);
 
             mInitialApplication = app;
+            final boolean updateHttpProxy;
+            synchronized (this) {
+                updateHttpProxy = mUpdateHttpProxyOnBind;
+                // This synchronized block ensures that any subsequent call to updateHttpProxy()
+                // will see a non-null mInitialApplication.
+            }
+            if (updateHttpProxy) {
+                ActivityThread.updateHttpProxy(app);
+            }
 
             // don't bring up providers in restricted mode; they may depend on the
             // app's custom Application class
```
