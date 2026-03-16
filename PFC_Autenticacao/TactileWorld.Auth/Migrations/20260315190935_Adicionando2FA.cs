using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace TactileWorld.Auth.Migrations
{
    /// <inheritdoc />
    public partial class Adicionando2FA : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "Is2FAEnabled",
                table: "Usuarios",
                type: "tinyint(1)",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "Secret2FA",
                table: "Usuarios",
                type: "longtext",
                nullable: true)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Is2FAEnabled",
                table: "Usuarios");

            migrationBuilder.DropColumn(
                name: "Secret2FA",
                table: "Usuarios");
        }
    }
}
