# -----------------------------------
# 🔨 Build stage
# -----------------------------------
FROM mcr.microsoft.com/dotnet/sdk:9.0-preview AS build
WORKDIR /src

# Copy and restore only the API project
COPY api/api.csproj ./
RUN dotnet restore api.csproj

# Copy API source and publish
COPY api/. ./
RUN dotnet publish api.csproj -c Release -o /app/out

# -----------------------------------
# 🚀 Runtime stage
# -----------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:9.0-preview
WORKDIR /app

# Tell Kestrel to bind to port 80
ENV ASPNETCORE_URLS=http://+:80

# Document the listening port
EXPOSE 80

# Copy the published output
COPY --from=build /app/out ./

ENTRYPOINT ["dotnet", "api.dll"]