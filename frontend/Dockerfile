#  PacketPulse — Frontend Dockerfile
#  This is a single-stage build using the official Nginx image.
#  nginx:alpine is used because:
#    - alpine = Alpine Linux, an extremely minimal Linux distro
#    - The image is only ~40MB vs ~190MB for nginx:latest
#    - No Python, no build tools, just Nginx
#  What happens:
#  1. Start from the nginx:alpine base image
#  2. Remove the default Nginx config
#  3. Copy our custom nginx.conf & Copy all frontend static files into the directory Nginx serves files from by default

FROM nginx:alpine

# 1. Remove default Nginx config so our template takes over
RUN rm /etc/nginx/conf.d/default.conf

# 1. Copy the static website files (HTML, CSS, JS)
COPY . /usr/share/nginx/html

# 2. Copy the template to the specific folder Nginx expects
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

# Document that this container serves on port 80
ENV BACKEND_URL=http://localhost:8000
EXPOSE 80