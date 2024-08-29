# urls.py
from django.urls import path
from .views import upload_file, save_computer_data, save_defender_status, save_defender_events, view_text_file
 
urlpatterns = [
    path("upload/", upload_file, name="upload_file"),
    path("api1/", save_computer_data, name="save_computer_data"),
    path('api1/defenderstatus/<str:serial>/', save_defender_status, name='save_defender_status'),
    path('api1/defender_events/<str:serial>/', save_defender_events, name='save_defender_events'),
    path('view_text_file/<str:serial>/', view_text_file, name='view_text_file'),

]
