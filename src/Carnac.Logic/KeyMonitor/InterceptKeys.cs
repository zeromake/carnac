using System;
using System.Diagnostics;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Windows.Forms;

namespace Carnac.Logic.KeyMonitor
{
    [PermissionSet(SecurityAction.LinkDemand, Name = "FullTrust")]
    [PermissionSet(SecurityAction.InheritanceDemand, Name = "FullTrust")]
    public class InterceptKeys : IInterceptKeys
    {
        public static readonly InterceptKeys Current = new InterceptKeys();
        readonly IObservable<InterceptKeyEventArgs> keyStream;
        // ReSharper disable once PrivateFieldCanBeConvertedToLocalVariable
        Win32Methods.LowLevelKeyboardProc callback;
        Win32Methods.LowLevelKeyboardProc mouseCallback;

        InterceptKeys()
        {
            keyStream = Observable.Create<InterceptKeyEventArgs>(observer =>
            {
                Debug.Write("Subscribed to keys");
                IntPtr[] hookId = null;
                // Need to hold onto this callback, otherwise it will get GC'd as it is an unmanged callback
                callback = (nCode, wParam, lParam) =>
                {
                    if (nCode >= 0) {
                        var eventArgs = CreateEventArgs(wParam, lParam);
                        observer.OnNext(eventArgs);
                        if (eventArgs.Handled)
                            return (IntPtr)1;
                    }
                    // ReSharper disable once AccessToModifiedClosure
                    return Win32Methods.CallNextHookEx(hookId[0], nCode, wParam, lParam);
                };
                mouseCallback = (nCode, wParam, lParam) =>
                {
                    if (nCode >= 0)
                    {
                        var eventArgs = CreateMouseEventArgs(wParam, lParam);
                        if (eventArgs != null)
                        {
                            observer.OnNext(eventArgs);
                            if (eventArgs.Handled)
                                return (IntPtr)1;
                        }
                    }
                    // ReSharper disable once AccessToModifiedClosure
                    return Win32Methods.CallNextHookEx(hookId[1], nCode, wParam, lParam);
                };
                hookId = SetHook(callback, mouseCallback);
                return Disposable.Create(() =>
                {
                    Debug.Write("Unsubscribed from keys");
                    foreach(var hook in hookId)
                    {
                        Win32Methods.UnhookWindowsHookEx(hook);
                    }
                    callback = null;
                    mouseCallback = null;
                });
            })
            .Publish().RefCount();
        }

        public IObservable<InterceptKeyEventArgs> GetKeyStream()
        {
            return keyStream;
        }
        static InterceptKeyEventArgs CreateMouseEventArgs(IntPtr wParam, IntPtr lParam)
        {
            if (wParam == (IntPtr)Win32Methods.WM_MOUSEMOVE)
            {
                return null;
            }
            int button = 0;
            if (wParam == (IntPtr)Win32Methods.WM_LBUTTONDOWN)
            {
                button |= 1;
            }
            if (wParam == (IntPtr)Win32Methods.WM_RBUTTONDOWN)
            {
                button |= 4;
            }
            if (wParam == (IntPtr)Win32Methods.WM_MBUTTONDOWN)
            {
                button |= 16;
            }
            if (button > 0)
            {
                return new InterceptKeyEventArgs(button);
            }
            return null;
        }

        static InterceptKeyEventArgs CreateEventArgs(IntPtr wParam, IntPtr lParam)
        {
            bool alt = (Control.ModifierKeys & Keys.Alt) != 0;
            bool control = (Control.ModifierKeys & Keys.Control) != 0;
            bool shift = (Control.ModifierKeys & Keys.Shift) != 0;
            bool keyDown = wParam == (IntPtr)Win32Methods.WM_KEYDOWN;
            bool keyUp = wParam == (IntPtr)Win32Methods.WM_KEYUP;
            int vkCode = Marshal.ReadInt32(lParam);
            var key = (Keys)vkCode;
            //http://msdn.microsoft.com/en-us/library/windows/desktop/ms646286(v=vs.85).aspx
            if (key != Keys.RMenu && key != Keys.LMenu && wParam == (IntPtr)Win32Methods.WM_SYSKEYDOWN)
            {
                alt = true;
                keyDown = true;
            }
            if (key != Keys.RMenu && key != Keys.LMenu && wParam == (IntPtr)Win32Methods.WM_SYSKEYUP)
            {
                alt = true;
                keyUp = true;
            }

            return new InterceptKeyEventArgs(
                key,
                keyDown ?
                KeyDirection.Down : keyUp
                ? KeyDirection.Up : KeyDirection.Unknown,
                alt, control, shift);
        }

        static IntPtr[] SetHook(Win32Methods.LowLevelKeyboardProc proc, Win32Methods.LowLevelKeyboardProc mouseCallback)
        {
            // NOTE: This requires FullTrust to use the Process class.
            //       There don't seem to be alternatives to achieving this in
            //       MediumTrust environment which is fine because that's a
            //       concept that has long been obsoleted. But just a warning
            //       if you ever try and run Carnac in that sort of way.
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                IntPtr code1 = Win32Methods.SetWindowsHookEx(Win32Methods.WH_KEYBOARD_LL, proc, Win32Methods.GetModuleHandle(curModule.ModuleName), 0);
                IntPtr code2 = Win32Methods.SetWindowsHookEx(Win32Methods.WH_MOUSE_LL, mouseCallback, Win32Methods.GetModuleHandle(curModule.ModuleName), 0);
                return new IntPtr[] { code1, code2 };
            }
        }
    }
}