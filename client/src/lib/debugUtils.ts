// Browser debugging utilities for OAuth authentication troubleshooting

export class AuthDebugger {
  private static instance: AuthDebugger;
  private startTime: number;
  private events: Array<{
    timestamp: number;
    type: string;
    data: any;
    userAgent: string;
    url: string;
  }> = [];

  constructor() {
    this.startTime = Date.now();
    this.initializeDebugger();
  }

  static getInstance(): AuthDebugger {
    if (!AuthDebugger.instance) {
      AuthDebugger.instance = new AuthDebugger();
    }
    return AuthDebugger.instance;
  }

  private initializeDebugger() {
    // Track page loads
    this.logEvent('page_load', {
      url: window.location.href,
      referrer: document.referrer,
      cookiesEnabled: navigator.cookieEnabled,
      storageAvailable: this.checkStorageAvailability()
    });

    // Track all clicks
    document.addEventListener('click', (event) => {
      const target = event.target as HTMLElement;
      this.logEvent('click', {
        element: target.tagName,
        className: target.className,
        id: target.id,
        textContent: target.textContent?.slice(0, 100),
        testId: target.getAttribute('data-testid'),
        isLoginButton: target.getAttribute('data-testid') === 'button-login'
      });
    });

    // Track navigation attempts (safer approach)
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;
    
    history.pushState = function(state: any, title: string, url?: string | URL | null) {
      AuthDebugger.getInstance().logEvent('navigation_pushstate', { url, state, title });
      return originalPushState.call(history, state, title, url);
    };

    history.replaceState = function(state: any, title: string, url?: string | URL | null) {
      AuthDebugger.getInstance().logEvent('navigation_replacestate', { url, state, title });
      return originalReplaceState.call(history, state, title, url);
    };

    // Track beforeunload (when user navigates away)
    window.addEventListener('beforeunload', (event) => {
      this.logEvent('before_unload', {
        currentUrl: window.location.href,
        event: 'navigation_starting'
      });
    });

    // Track network requests
    this.interceptFetch();
    this.interceptXHR();

    // Track visibility changes
    document.addEventListener('visibilitychange', () => {
      this.logEvent('visibility_change', {
        hidden: document.hidden,
        visibilityState: document.visibilityState
      });
    });

    // Track errors
    window.addEventListener('error', (event) => {
      this.logEvent('javascript_error', {
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        stack: event.error?.stack
      });
    });

    // Track unhandled promise rejections
    window.addEventListener('unhandledrejection', (event) => {
      this.logEvent('unhandled_rejection', {
        reason: event.reason,
        promise: String(event.promise)
      });
    });
  }

  private checkStorageAvailability(): any {
    try {
      const test = '__storage_test__';
      localStorage.setItem(test, test);
      localStorage.removeItem(test);
      return {
        localStorage: true,
        sessionStorage: typeof sessionStorage !== 'undefined',
        cookies: navigator.cookieEnabled
      };
    } catch (error) {
      return {
        localStorage: false,
        sessionStorage: false,
        cookies: navigator.cookieEnabled,
        error: String(error)
      };
    }
  }

  private interceptFetch() {
    const originalFetch = window.fetch;
    window.fetch = async function(input: RequestInfo | URL, init?: RequestInit) {
      const url = typeof input === 'string' ? input : input.toString();
      const startTime = Date.now();
      
      AuthDebugger.getInstance().logEvent('fetch_start', {
        url,
        method: init?.method || 'GET',
        headers: init?.headers
      });

      try {
        const response = await originalFetch(input, init);
        const endTime = Date.now();
        
        AuthDebugger.getInstance().logEvent('fetch_complete', {
          url,
          status: response.status,
          statusText: response.statusText,
          duration: endTime - startTime,
          headers: Object.fromEntries(response.headers.entries())
        });
        
        return response;
      } catch (error) {
        AuthDebugger.getInstance().logEvent('fetch_error', {
          url,
          error: String(error),
          duration: Date.now() - startTime
        });
        throw error;
      }
    };
  }

  private interceptXHR() {
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method: string, url: string | URL, async?: boolean) {
      (this as any)._debugUrl = url;
      (this as any)._debugMethod = method;
      (this as any)._debugStartTime = Date.now();
      
      AuthDebugger.getInstance().logEvent('xhr_open', {
        method,
        url: String(url)
      });
      
      return originalXHROpen.call(this, method, url, async ?? true);
    };

    XMLHttpRequest.prototype.send = function(body?: Document | XMLHttpRequestBodyInit | null) {
      const debugUrl = (this as any)._debugUrl;
      const debugMethod = (this as any)._debugMethod;
      
      this.addEventListener('load', function() {
        AuthDebugger.getInstance().logEvent('xhr_complete', {
          url: debugUrl,
          method: debugMethod,
          status: this.status,
          statusText: this.statusText,
          duration: Date.now() - (this as any)._debugStartTime
        });
      });

      this.addEventListener('error', function() {
        AuthDebugger.getInstance().logEvent('xhr_error', {
          url: debugUrl,
          method: debugMethod,
          duration: Date.now() - (this as any)._debugStartTime
        });
      });

      return originalXHRSend.call(this, body);
    };
  }

  private logEvent(type: string, data: any) {
    const event = {
      timestamp: Date.now(),
      type,
      data,
      userAgent: navigator.userAgent,
      url: window.location.href
    };
    
    this.events.push(event);
    console.log(`🔍 [Browser Debug] ${type}:`, data);
    
    // Keep only last 100 events to prevent memory bloat
    if (this.events.length > 100) {
      this.events = this.events.slice(-100);
    }
  }

  // Public methods for manual debugging
  getEvents(): typeof this.events {
    return [...this.events];
  }

  getEventsSince(timestamp: number): typeof this.events {
    return this.events.filter(event => event.timestamp >= timestamp);
  }

  exportDebugData(): string {
    return JSON.stringify({
      startTime: this.startTime,
      currentTime: Date.now(),
      duration: Date.now() - this.startTime,
      events: this.events,
      browserInfo: {
        userAgent: navigator.userAgent,
        cookieEnabled: navigator.cookieEnabled,
        language: navigator.language,
        platform: navigator.platform,
        url: window.location.href,
        referrer: document.referrer
      }
    }, null, 2);
  }

  async checkAuthState(): Promise<any> {
    try {
      // Check session diagnostics
      const sessionResponse = await fetch('/api/debug/session');
      const sessionData = await sessionResponse.json();
      
      // Check user auth state
      const userResponse = await fetch('/api/auth/user');
      const userData = userResponse.ok ? await userResponse.json() : null;
      
      const authState = {
        session: sessionData,
        user: userData,
        userResponseStatus: userResponse.status,
        timestamp: Date.now()
      };
      
      this.logEvent('auth_state_check', authState);
      return authState;
    } catch (error) {
      const authError = {
        error: String(error),
        timestamp: Date.now()
      };
      this.logEvent('auth_state_error', authError);
      return authError;
    }
  }

  // Clear debug data
  clearEvents() {
    this.events = [];
    this.logEvent('debug_cleared', { timestamp: Date.now() });
  }
}

// Initialize debugger automatically
export const authDebugger = AuthDebugger.getInstance();

// Make it available globally for console debugging
(window as any).authDebugger = authDebugger;

console.log('🔍 [Browser Debug] Authentication debugger initialized. Use window.authDebugger for manual debugging.');