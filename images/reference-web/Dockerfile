FROM nginx:1.27-alpine

LABEL org.opencontainers.image.title="AZ-06 Reference Web Decoy" \
      org.opencontainers.image.description="Synthetic non-production web surface for Azazel-Deception Phase-1 portability validation" \
      org.opencontainers.image.source="https://github.com/01rabbit/Azazel-Deception" \
      org.opencontainers.image.licenses="MIT"

COPY runtime/compose/nginx.conf /etc/nginx/nginx.conf
COPY runtime/compose/html/ /usr/share/nginx/html/

USER 101:101
EXPOSE 8080

CMD ["nginx", "-g", "daemon off;"]
