//go:build darwin && cgo

package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa -framework QuartzCore
#import <Cocoa/Cocoa.h>
#import <QuartzCore/QuartzCore.h>

static void roundMainWindow(double radius) {
	dispatch_async(dispatch_get_main_queue(), ^{
		for (NSWindow *window in NSApp.windows) {
			if (![window.title isEqualToString:@"Evasion"]) continue;
			window.opaque = NO;
			window.backgroundColor = NSColor.clearColor;
			NSView *view = window.contentView;
			view.wantsLayer = YES;
			view.layer.cornerRadius = radius;
			view.layer.masksToBounds = YES;
			[window invalidateShadow];
			break;
		}
	});
}
*/
import "C"

import "context"

func configureWindowCorners(context.Context) { C.roundMainWindow(C.double(mainCornerRadius)) }
