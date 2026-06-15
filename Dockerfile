# ---- build stage ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# restore first (better layer caching)
COPY ["CertifyLab.csproj", "./"]
RUN dotnet restore

# build + publish
COPY . .
RUN dotnet publish "CertifyLab.csproj" -c Release -o /app /p:UseAppHost=false

# ---- runtime stage ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app ./

ENV ASPNETCORE_URLS=http://0.0.0.0:8080
ENV CERTIFY_DB=/tmp/certify.db
EXPOSE 8080

ENTRYPOINT ["dotnet", "CertifyLab.dll"]
