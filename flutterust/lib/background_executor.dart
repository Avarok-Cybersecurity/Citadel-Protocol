
import 'package:background_fetch/background_fetch.dart';
import 'package:flutterust/utils.dart';

class BackgroundExecutor {
  static final config = BackgroundFetchConfig(minimumFetchInterval: 15, stopOnTerminate: false, enableHeadless: true, startOnBoot: true, requiredNetworkType: NetworkType.ANY);
  static Future<void> setupBackground() async {
    await BackgroundFetch.configure(config, poll, onTimeout);
    await BackgroundFetch.registerHeadlessTask(headlessExecution);
  }

  static void poll(String taskId) async {
    print("[Background Executor] Running 15m periodic poll for task $taskId");
    //Utils.pushNotification("Running background task", taskId);
    BackgroundFetch.finish(taskId);
  }

  static void onTimeout(String taskId) {
    print("Timeout on background task $taskId");
  }
}

/// This function is ran when the app is terminated. Its goal is to check for background messages etc
void headlessExecution(HeadlessTask task) async {
  BackgroundExecutor.poll(task.taskId);
}