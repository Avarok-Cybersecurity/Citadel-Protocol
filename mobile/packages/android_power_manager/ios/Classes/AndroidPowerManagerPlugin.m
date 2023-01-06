#import "AndroidPowerManagerPlugin.h"

@implementation AndroidPowerManagerPlugin
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  FlutterMethodChannel* channel = [FlutterMethodChannel
      methodChannelWithName:@"androidpowermanager"
            binaryMessenger:[registrar messenger]];
  AndroidPowerManagerPlugin* instance = [[AndroidPowerManagerPlugin alloc] init];
  [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall*)call result:(FlutterResult)result {
    result(FlutterMethodNotImplemented);
}

@end
