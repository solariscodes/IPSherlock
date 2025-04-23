from PIL import Image, ImageDraw, ImageFont
import os

# Dimensões da imagem (padrão para Open Graph)
width, height = 1200, 630

# Criar uma nova imagem com fundo azul (#4a6fa5)
image = Image.new('RGB', (width, height), color=(74, 111, 165))
draw = ImageDraw.Draw(image)

# Tentar carregar fontes (se não estiverem disponíveis, usará a fonte padrão)
try:
    # Tente carregar a fonte Arial ou use a fonte padrão
    title_font = ImageFont.truetype("arial.ttf", 72)
    subtitle_font = ImageFont.truetype("arial.ttf", 36)
except IOError:
    # Usar fonte padrão se Arial não estiver disponível
    title_font = ImageFont.load_default()
    subtitle_font = ImageFont.load_default()

# Adicionar texto centralizado
title = "IPSherlock"
subtitle = "The Detective for IP Addresses & Domains"

# Calcular posição para centralizar o texto
title_width = draw.textlength(title, font=title_font)
subtitle_width = draw.textlength(subtitle, font=subtitle_font)

title_position = ((width - title_width) // 2, 280)
subtitle_position = ((width - subtitle_width) // 2, 380)

# Desenhar texto
draw.text(title_position, title, font=title_font, fill=(255, 255, 255))
draw.text(subtitle_position, subtitle, font=subtitle_font, fill=(255, 255, 255))

# Desenhar um círculo representando uma lupa (símbolo de detetive)
draw.ellipse((550, 130, 650, 230), fill=(26, 42, 58))  # Cor secundária #1a2a3a

# Salvar a imagem
image_path = os.path.join('static', 'img', 'og-image.png')
image.save(image_path)

print(f"Imagem de Open Graph criada com sucesso: {image_path}")
