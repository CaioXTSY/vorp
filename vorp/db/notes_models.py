from django.db import models
from django.utils import timezone
from django.conf import settings
import hashlib
from django.utils.text import slugify

def generate_share_hash(note_id, secret):
    return hashlib.sha256(f"{note_id}-{secret}".encode('utf-8')).hexdigest()[:10]

class Note(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='notes'
    )
    title = models.CharField(max_length=200)
    slug = models.SlugField(max_length=100, unique=True)
    share_hash = models.CharField(max_length=64, unique=True, null=True, blank=True)
    content = models.TextField()
    is_public = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    views = models.PositiveIntegerField(default=0)

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        
        if not self.slug:
            base_slug = slugify(self.title)
            slug_candidate = base_slug
            counter = 1
            
            while self.__class__.objects.filter(slug=slug_candidate).exclude(pk=self.pk).exists():
                slug_candidate = f"{base_slug}-{counter}"
                counter += 1
            self.slug = slug_candidate

        
        if not self.pk:
            force_insert = kwargs.pop('force_insert', False)
            super().save(force_insert=force_insert, *args, **kwargs)

        
        if not self.share_hash:
            secret = settings.SECRET_KEY
            self.share_hash = generate_share_hash(self.id, secret)
                    
        kwargs.pop('force_insert', None)
        super().save(*args, **kwargs)
