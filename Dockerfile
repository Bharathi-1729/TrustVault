# Multi-stage Dockerfile for TrustVault Enterprise Web API & SPA
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["backend/TrustVault.Api/TrustVault.Api.csproj", "backend/TrustVault.Api/"]
RUN dotnet restore "backend/TrustVault.Api/TrustVault.Api.csproj"
COPY . .
WORKDIR "/src/backend/TrustVault.Api"
RUN dotnet publish "TrustVault.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
EXPOSE 5000
ENV ASPNETCORE_URLS=http://+:5000
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "TrustVault.Api.dll"]
