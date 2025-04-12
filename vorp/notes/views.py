from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, FileResponse
from django.urls import reverse
from io import BytesIO
import markdown
from xhtml2pdf import pisa
from db.notes_models import Note

@login_required
def list_notes(request):
    notes = Note.objects.filter(user=request.user).order_by('-updated_at')
    return render(request, 'notes/list_notes.html', {'notes': notes})

@login_required
def new_note(request):
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        if not title:
            messages.error(request, "O título não pode estar vazio.")
            return redirect('notes:list_notes')
        note = Note.objects.create(
            user=request.user,
            title=title,
            content="",
            is_public=False
        )
        messages.success(request, "Nota criada com sucesso!")
        return redirect('notes:list_notes')
    return render(request, 'notes/new_note.html')

@login_required
def view_note(request, note_id):
    note = get_object_or_404(Note, pk=note_id)
    if not note.is_public and note.user != request.user:
        messages.error(request, "Esta nota é privada.")
        return redirect('accounts:login')

    note.views += 1
    note.save(update_fields=['views'])

    html_content = markdown.markdown(note.content, extensions=['fenced_code', 'tables', 'toc', 'codehilite'])
    return render(request, 'notes/view_note.html', {
        'note': note,
        'html_content': html_content,
    })

@login_required
def edit_note(request, note_id):
    note = get_object_or_404(Note, pk=note_id, user=request.user)
    if request.method == 'POST':
        note.title = request.POST.get('title', note.title).strip()
        note.content = request.POST.get('content', note.content)
        note.is_public = (request.POST.get('is_public') == 'on')
        note.save()
        messages.success(request, "Nota atualizada com sucesso!")
        return redirect('notes:view_note', note_id=note.id)
    return render(request, 'notes/edit_note.html', {'note': note})

@login_required
def delete_note(request, note_id):
    note = get_object_or_404(Note, pk=note_id, user=request.user)
    note.delete()
    messages.success(request, "Nota excluída com sucesso.")
    return redirect('notes:list_notes')

@login_required
def toggle_public(request, note_id):
    if request.method == 'POST':
        note = get_object_or_404(Note, pk=note_id, user=request.user)
        note.is_public = not note.is_public
        note.save()
        share_link = ''
        if note.is_public:
            share_link = request.build_absolute_uri(reverse('notes:public_note', args=[note.share_hash]))
        return JsonResponse({'status': 'success', 'share_link': share_link})
    return JsonResponse({'status': 'error', 'message': 'Método inválido'}, status=405)

def public_note(request, share_hash):
    note = get_object_or_404(Note, share_hash=share_hash, is_public=True)
    note.views += 1
    note.save(update_fields=['views'])

    html_content = markdown.markdown(note.content, extensions=['fenced_code', 'tables', 'toc', 'codehilite'])
    return render(request, 'notes/view_note.html', {
        'note': note,
        'html_content': html_content,
    })

def export_note(request, note_id):
    note = get_object_or_404(Note, pk=note_id)
    if not note.is_public and (not request.user.is_authenticated or note.user != request.user):
        messages.error(request, "Acesso negado para exportar esta nota.")
        return redirect('accounts:login')

    html_content = markdown.markdown(note.content, extensions=['fenced_code', 'tables', 'codehilite'])
    css = """
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 2cm;
            font-size: 12pt;
        }
        h1 { font-size: 18pt; }
        h2 { font-size: 16pt; }
        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
            overflow-x: auto;
            font-family: Consolas, monospace;
            font-size: 10pt;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #dee2e6;
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
    </style>
    """
    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>{note.title}</title>
        {css}
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """
    pdf_buffer = BytesIO()
    pisa.CreatePDF(BytesIO(full_html.encode('utf-8')), pdf_buffer)
    pdf_buffer.seek(0)
    response = FileResponse(pdf_buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{note.title}.pdf"'
    return response
