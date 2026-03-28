from django.contrib import admin
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LoginView, LogoutView
from collections import defaultdict
import time

# ── In-memory brute-force guard ───────────────────────────────────────────────
_FAILED_ATTEMPTS  = defaultdict(list)
_MAX_ATTEMPTS     = 5
_LOCKOUT_SECONDS  = 300   # 5 minutes

class RateLimitedLoginView(LoginView):
    template_name = 'registration/login.html'

    def _client_ip(self) -> str:
        xff = self.request.META.get('HTTP_X_FORWARDED_FOR', '')
        return xff.split(',')[0].strip() if xff else self.request.META.get('REMOTE_ADDR', '0.0.0.0')

    def _prune(self, ip: str):
        now = time.time()
        _FAILED_ATTEMPTS[ip] = [t for t in _FAILED_ATTEMPTS[ip]
                                  if now - t < _LOCKOUT_SECONDS]

    def _locked_out_response(self, mins: int):
        from django.http import HttpResponse
        return HttpResponse(
            f'''<!DOCTYPE html><html>
            <body style="background:#0d1117;color:#f85149;font-family:monospace;
                         display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
              <div style="text-align:center">
                <div style="font-size:3rem">🔒</div>
                <h1>IP LOCKED OUT</h1>
                <p>Too many failed login attempts.</p>
                <p>Try again in <strong>{mins} minutes</strong>.</p>
              </div>
            </body></html>''',
            status=429,
            content_type='text/html',
        )

    def dispatch(self, request, *args, **kwargs):
        ip = self._client_ip()
        self._prune(ip)
        if len(_FAILED_ATTEMPTS[ip]) >= _MAX_ATTEMPTS:
            remaining_wait = _LOCKOUT_SECONDS - int(time.time() - _FAILED_ATTEMPTS[ip][0])
            remaining_mins = max(1, (remaining_wait + 59) // 60)
            return self._locked_out_response(remaining_mins)
        return super().dispatch(request, *args, **kwargs)

    def form_invalid(self, form):
        ip = self._client_ip()
        self._prune(ip)
        _FAILED_ATTEMPTS[ip].append(time.time())
        attempts_left = max(0, _MAX_ATTEMPTS - len(_FAILED_ATTEMPTS[ip]))
        # Attach remaining count so the template can display it
        form._attempts_left = attempts_left
        if attempts_left == 0:
            return self._locked_out_response(_LOCKOUT_SECONDS // 60)
        return super().form_invalid(form)


urlpatterns = [
    path('admin/',  admin.site.urls),
    path('login/',  RateLimitedLoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(),           name='logout'),
    path('',        include('scanner.urls')),
]