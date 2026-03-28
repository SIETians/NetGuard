from django.urls import path
from . import views

urlpatterns = [
    path('',                       views.index,               name='index'),
    path('api/system/',            views.host_fingerprint,    name='system_info'),
    path('api/arp/',               views.arp_discover,        name='arp_discover'),
    path('api/scan/',              views.scan_target,         name='scan_target'),
    path('api/chat/',              views.ai_chat,             name='ai_chat'),
    path('api/download-script/',   views.download_host_script, name='download_script'),
    # Phase 5: dedicated Groq-powered .bat download endpoint
    path('api/kill-ports/',        views.kill_ports_script,   name='kill_ports'),
]