from django.shortcuts import render

def index(request):
    return render(request, 'core/index.html')

def mvv(request):
    return render(request, 'core/mvv.html')

def pitch(request):
    return render(request, 'core/pitch.html')