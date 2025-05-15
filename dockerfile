FROM nginx:alpine
COPY . /usr/share/nginx/html
COPY level_4 /usr/share/nginx/html/level_4/TemplateData
COPY level_1 /usr/share/nginx/html/level_1/images
COPY level_2 /usr/share/nginx/html/level_2/TemplateData
EXPOSE 80
