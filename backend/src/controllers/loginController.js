/*
Como vamos a validar si es cliente o empleado,
entonces importo ambos modelos
*/
import CustomersModel from "../models/customers.js";
import EmployeesModel from "../models/employee.js";
import bcryptjs from "bcryptjs";
import jsonwebtoken from "jsonwebtoken";
import { config } from "../config.js";

const loginController = {};

// Declarar dos constantes
const maxAttempts = 3; // máximo de intentos
const lockTime = 15 * 60 * 1000; // 15 minutos

loginController.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    let userFound; // Variable que dice si encontramos un usuario
    let userType;  // Variable que dice qué tipo de usuario es

    // 1. Admin
    if (
      email === config.emailAdmin.email &&
      password === config.emailAdmin.password
    ) {
      userType = "Admin";
      userFound = { _id: "Admin" }; // simulamos usuario admin
    } else {
      // 2. Empleado
      userFound = await EmployeesModel.findOne({ email });
      userType = "Employee";

      // 3. Cliente
      if (!userFound) {
        userFound = await CustomersModel.findOne({ email });
        userType = "Customer";
      }
    }

    // Si no encontramos un usuario en ningún lado
    if (!userFound) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verificar si la cuenta está bloqueada (solo clientes/empleados)
    if (userType !== "Admin") {
      if (userFound.lockTime && userFound.lockTime > Date.now()) {
        const minutosRestantes = Math.ceil(
          (userFound.lockTime - Date.now()) / 60000
        );
        return res.status(403).json({
          message: `Cuenta bloqueada, intenta de nuevo en ${minutosRestantes} minutos`,
        });
      }
    }

    // Validar contraseña (solo clientes/empleados)
    if (userType !== "Admin") {
      const isMatch = await bcryptjs.compare(password, userFound.password);
      if (!isMatch) {
        // Incrementar intentos fallidos
        userFound.loginAttempts = (userFound.loginAttempts || 0) + 1;

        if (userFound.loginAttempts >= maxAttempts) {
          userFound.lockTime = Date.now() + lockTime;
          await userFound.save();
          return res.status(403).json({ message: "Usuario bloqueado" });
        }

        await userFound.save();
        return res.status(401).json({ message: "Invalid password" });
      }

      // Resetear intentos y lockTime si fue correcto
      userFound.loginAttempts = 0;
      userFound.lockTime = null;
      await userFound.save();
    }

    // ✅ Generar token y guardarlo en variable
    const token = jsonwebtoken.sign(
      { id: userFound._id, userType },
      config.JWT.secret,
      { expiresIn: config.JWT.expiresIn }
    );

    // Guardar token en cookie
    res.cookie("authToken", token, {
      maxAge: 24 * 60 * 60 * 1000, // 1 día
      path: "/",
      sameSite: "lax",
    });

    // Responder con éxito
    return res.json({
      message: "Login successful",
      userType,
    });
  } catch (error) {
    console.error("Error en login:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

export default loginController;