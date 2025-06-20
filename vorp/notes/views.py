from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, FileResponse
from django.urls import reverse
from io import BytesIO
import markdown
from xhtml2pdf import pisa
from db.notes_models import Note, Tag, Comment
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
import openai
import json

@login_required
def list_notes(request):
    notes = Note.objects.filter(user=request.user).order_by('-updated_at')
    
    # Get all unique tags with counts for this user
    from django.db.models import Count
    all_tags = Tag.objects.filter(
        notes__user=request.user  # Changed from note__user to notes__user
    ).annotate(
        count=Count('notes')      # Changed from Count('note') to Count('notes')
    ).order_by('-count', 'name')
    
    return render(request, 'notes/list_notes.html', {
        'notes': notes,
        'all_tags': all_tags
    })

@login_required
def new_note(request):
    if request.method == 'POST':
        title = request.POST.get('title', '').strip()
        tags_str = request.POST.get('tags', '')
        if not title:
            messages.error(request, "O título não pode estar vazio.")
            return redirect('notes:list_notes')
        note = Note.objects.create(
            user=request.user,
            title=title,
            content="",
            is_public=False
        )
        tags = [t.strip() for t in tags_str.split(',') if t.strip()]
        tag_objs = []
        for tag_name in tags:
            tag_obj, _ = Tag.objects.get_or_create(user=request.user, name=tag_name)
            tag_objs.append(tag_obj)
        note.tags.set(tag_objs)
        messages.success(request, "Nota criada com sucesso!")
        return redirect('notes:list_notes')
    return render(request, 'notes/new_note.html')

@login_required
def view_note(request, note_id):
    note = get_object_or_404(Note, pk=note_id)
    if not note.is_public and note.user != request.user:
        messages.error(request, "Esta nota é privada.")
        return redirect('accounts:login')

    # adiciona comentário
    if request.method == 'POST' and 'comment_text' in request.POST:
        text = request.POST.get('comment_text', '').strip()
        if text:
            Comment.objects.create(note=note, user=request.user, text=text)
            messages.success(request, "Comentário adicionado!")
            return redirect('notes:view_note', note_id=note.id)

    # incrementa visualizações
    note.views += 1
    note.save(update_fields=['views'])

    # configura o parser de Markdown com TOC
    md = markdown.Markdown(
        extensions=['fenced_code', 'tables', 'codehilite', 'toc'],
        extension_configs={
            'toc': {
                'permalink': True,
                'baselevel': 2
            }
        }
    )
    html_content = md.convert(note.content)
    toc_html = md.toc

    comments = note.comments.select_related('user').all()
    return render(request, 'notes/view_note.html', {
        'note': note,
        'html_content': html_content,
        'toc': toc_html,
        'comments': comments,
    })

@login_required
def edit_note(request, note_id):
    note = get_object_or_404(Note, pk=note_id, user=request.user)
    if request.method == 'POST':
        note.title = request.POST.get('title', note.title).strip()
        note.content = request.POST.get('content', note.content)
        note.is_public = (request.POST.get('is_public') == 'on')
        tags_str = request.POST.get('tags', '')
        tags = [t.strip() for t in tags_str.split(',') if t.strip()]
        tag_objs = []
        for tag_name in tags:
            tag_obj, _ = Tag.objects.get_or_create(user=request.user, name=tag_name)
            tag_objs.append(tag_obj)
        note.tags.set(tag_objs)
        note.save()
        messages.success(request, "Nota atualizada com sucesso!")
        return redirect('notes:view_note', note_id=note.id)
    tags = ', '.join([tag.name for tag in note.tags.all()])
    return render(request, 'notes/edit_note.html', {'note': note, 'tags': tags})

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

    # parser de Markdown com TOC para público
    md = markdown.Markdown(
        extensions=['fenced_code', 'tables', 'codehilite', 'toc'],
        extension_configs={
            'toc': {
                'permalink': True,
                'baselevel': 2
            }
        }
    )
    html_content = md.convert(note.content)
    toc_html = md.toc

    return render(request, 'notes/view_note.html', {
        'note': note,
        'html_content': html_content,
        'toc': toc_html,
    })

def export_note(request, note_id):
    note = get_object_or_404(Note, pk=note_id)
    if not note.is_public and (not request.user.is_authenticated or note.user != request.user):
        messages.error(request, "Acesso negado para exportar esta nota.")
        return redirect('accounts:login')

    html_content = markdown.markdown(note.content, extensions=['fenced_code', 'tables', 'codehilite'])
    css = """
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 2cm; font-size: 12pt; }
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
        th { background-color: #f8f9fa; font-weight: bold; }
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

@csrf_exempt
@require_POST
def ask(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        question = data.get('question', '')
        context = data.get('context', '')
        conversation_history = data.get('history', [])[-10:]

        messages_payload = [{
            "role": "system",
            "content": (
                "Você é Vorp, um assistente de estudos eficiente, focado e profissional.\n\n"
                "CONTEXTO:\n"
                f"{context}\n\n"
                "DIRETRIZES DE RESPOSTA:\n"
                "1. Estilo\n"
                "- Seja direto e objetivo\n"
                "- Máximo 2 parágrafos por resposta\n"
                "- Tom profissional e educativo\n"
                "- Evite jargões técnicos desnecessários\n\n"
                "2. Formatação\n"
                "- Use Markdown para estruturar o conteúdo\n"
                "- Aplique listas numeradas ou marcadores quando apropriado\n"
                "- Utilize negrito para pontos importantes\n"
                "- Organize com cabeçalhos e subcabeçalhos\n"
                "- Inclua tabelas para dados estruturados\n"
                "- Adicione links relevantes quando necessário\n\n"
                "3. Metodologia\n"
                "- Para perguntas não claras: solicite esclarecimentos\n"
                "- Para tópicos complexos: divida em subtópicos\n"
                "- Para conceitos técnicos: forneça explicações concisas\n"
                "- Para temas polêmicos: mantenha neutralidade\n"
                "- Para assuntos fora do escopo: decline educadamente\n\n"
                "FORMATO PARA QUESTÕES:\n"
                "### Questão\n"
                "- **Tema:** [Tema]\n"
                "- **Enunciado:** [Pergunta]\n\n"
                "### Alternativas (se aplicável)\n"
                "A) [Texto]\n"
                "B) [Texto]\n"
                "C) [Texto]\n"
                "D) [Texto]\n"
                "E) [Texto]\n\n"
                "### Resolução\n"
                "- **Resposta correta:** [Alternativa]\n"
                "- **Justificativa:** [Explicação]\n"
                "- **Dicas:** [Sugestões práticas]\n"
            )
        }]
        for msg in conversation_history:
            role = msg.get("role", "user").lower()
            if role not in ["system", "user", "assistant"]:
                role = "user"
            messages_payload.append({
                "role": role,
                "content": msg.get("content", "")
            })
        messages_payload.append({"role": "user", "content": question})

        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=messages_payload,
            temperature=0.4,
            max_tokens=5000
        )
        answer = response.choices[0].message.content
        return JsonResponse({'answer': answer})
    except Exception:
        return JsonResponse({'error': 'Erro ao processar a pergunta'}, status=500)

@csrf_exempt
@require_POST
def process_ai(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        action = data.get('action', '')
        text = data.get('text', '')
        if not action or not text:
            return JsonResponse({'error': 'Parâmetros inválidos'}, status=400)

        if action == 'summarize':
            system_prompt = "Você é um assistente especializado em resumir textos. Crie um resumo conciso do texto fornecido, mantendo os pontos principais."
            user_prompt = f"Resuma o seguinte texto em um parágrafo curto:\n\n{text}"
        elif action == 'enhance':
            system_prompt = "Você é um assistente especializado em melhorar a escrita. Melhore o texto fornecido, mantendo o significado original, mas tornando-o mais claro, conciso e profissional."
            user_prompt = f"Melhore o seguinte texto:\n\n{text}"
        elif action == 'format-md':
            system_prompt = "Você é um assistente especializado em formatação Markdown. Converta o texto fornecido em Markdown bem formatado, adicionando cabeçalhos, listas, ênfase e outros elementos apropriados."
            user_prompt = f"Converta o seguinte texto em Markdown bem formatado:\n\n{text}"
        elif action == 'explain':
            system_prompt = "Você é um assistente educacional especializado em explicar conceitos de forma clara e concisa."
            user_prompt = f"Explique o seguinte conceito de forma simples e educativa:\n\n{text}"
        elif action == 'translate':
            system_prompt = "Você é um assistente especializado em tradução. Traduza o texto fornecido para o português, mantendo o significado e o tom originais."
            user_prompt = f"Traduza o seguinte texto para o português:\n\n{text}"
        else:
            return JsonResponse({'error': 'Ação não reconhecida'}, status=400)

        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.4,
            max_tokens=2000
        )
        result = response.choices[0].message.content
        return JsonResponse({'result': result})
    except Exception:
        return JsonResponse({'error': 'Erro ao processar a solicitação'}, status=500)
