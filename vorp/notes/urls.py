from django.urls import path
from . import views

app_name = 'notes'

urlpatterns = [
    path('', views.list_notes, name='list_notes'),
    path('new/', views.new_note, name='new_note'),
    path('<int:note_id>/', views.view_note, name='view_note'),
    path('<int:note_id>/edit/', views.edit_note, name='edit_note'),
    path('<int:note_id>/delete/', views.delete_note, name='delete_note'),
    path('<int:note_id>/toggle_public/', views.toggle_public, name='toggle_public'),
    path('p/<str:share_hash>/', views.public_note, name='public_note'),
    path('export/<int:note_id>/', views.export_note, name='export_note'),
]
