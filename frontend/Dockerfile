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

# Remove the default Nginx config that comes with the image
# If we don't do this, Nginx would use its default config
# instead of ours, and the /api/ proxy wouldn't work
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom Nginx config into place
COPY nginx.conf.template /etc/nginx/templates/packetpulse.conf.template

# Copy all frontend files into Nginx's serving directory
# Nginx serves files from /usr/share/nginx/html by default
COPY . /usr/share/nginx/html/

<<<<<<< HEAD
EXPOSE 80
=======
# Document that this container serves on port 80
ENV BACKEND_URL=http://localhost:8000
EXPOSE 80
>>>>>>> f4a685810492c670bd2d7ac3beb34fcb5a93c989
