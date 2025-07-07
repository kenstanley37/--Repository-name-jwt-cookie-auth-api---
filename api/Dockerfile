# -----------------------------------
# 🔨 Build stage
# -----------------------------------
FROM mcr.microsoft.com/dotnet/sdk:9.0-preview AS build
WORKDIR /app

# Copy only the API project file and restore dependencies
COPY api.csproj ./
RUN dotnet restore api.csproj

# Copy all source files and publish only the API project
COPY . ./
RUN dotnet publish api.csproj -c Release -o out

# -----------------------------------
# 🚀 Runtime stage
# -----------------------------------
FROM mcr.microsoft.com/dotnet/aspnet:9.0-preview
WORKDIR /app
COPY --from=build /app/out ./

ENTRYPOINT ["dotnet", "api.dll"]