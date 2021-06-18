
import 'package:background_fetch/background_fetch.dart';
import 'package:flutterust/main.dart';
import 'package:flutterust/misc/message_send_handler.dart';

class BackgroundExecutor {
  static final config = BackgroundFetchConfig(minimumFetchInterval: 15, stopOnTerminate: false, enableHeadless: true, startOnBoot: true, requiredNetworkType: NetworkType.ANY);
  static bool ignoredFirst = false;
  static Future<void> setupBackground() async {
    await BackgroundFetch.configure(config, poll, onTimeout);
    await BackgroundFetch.registerHeadlessTask(headlessExecution);
  }

  static void poll(String taskId) async {
    if (!ignoredFirst) {
      ignoredFirst = true;
      BackgroundFetch.finish(taskId);
      return;
    }

    print("[Background Executor] Running 15m periodic poll for task $taskId");
    // make sure bridge is not null
    await RustSubsystem.init();
    await MessageSendHandler.poll();
    //Utils.pushNotification("Running background task", taskId);
    BackgroundFetch.finish(taskId);
  }

  static void onTimeout(String taskId) {
    print("Timeout on background task $taskId");
  }
}

/// This function is ran when the app is terminated. Its goal is to check for background messages etc
void headlessExecution(HeadlessTask task) async {
  print("[Headless executor]");
  BackgroundExecutor.poll(task.taskId);
}