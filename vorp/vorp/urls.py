from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

# Importe a view ask diretamente, para expô‑la em /
from notes import views as notes_views

urlpatterns = [
    # admin do Django
    path('admin/', admin.site.urls),

    # suas apps normais
    path('', include('core.urls',    namespace='core')),
    path('accounts/', include('accounts.urls', namespace='accounts')),
    path('notes/',    include('notes.urls',    namespace='notes')),

    # monta /ask/ apontando para notes.views.ask
    path('ask/', notes_views.ask, name='ask'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,  document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)