/**
 * Vtable Discovery Demo - C++ Binary with Virtual Classes
 *
 * This binary demonstrates various C++ OOP patterns with vtables:
 * - Multiple classes with virtual methods
 * - Inheritance hierarchy (base + derived)
 * - Virtual destructors
 * - Pure virtual methods (abstract base classes)
 * - Multiple inheritance (diamond pattern)
 *
 * Compile with: g++ -O1 -fno-inline -o input vtable_demo.cpp
 * Note: -fno-inline helps preserve function boundaries for analysis
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>

// =============================================================================
// Base Abstract Class: IShape
// =============================================================================
class IShape {
public:
    virtual ~IShape() {}
    virtual void draw() const = 0;           // Pure virtual
    virtual double area() const = 0;         // Pure virtual
    virtual const char* name() const = 0;    // Pure virtual
    virtual void scale(double factor) = 0;   // Pure virtual
};

// =============================================================================
// Base Abstract Class: ISerializable
// =============================================================================
class ISerializable {
public:
    virtual ~ISerializable() {}
    virtual void serialize(char* buffer, size_t size) const = 0;  // Pure virtual
    virtual void deserialize(const char* buffer) = 0;              // Pure virtual
};

// =============================================================================
// Concrete Class: Circle (inherits from IShape)
// =============================================================================
class Circle : public IShape {
private:
    double radius_;
    double x_, y_;  // center position

public:
    Circle(double r, double x = 0, double y = 0)
        : radius_(r), x_(x), y_(y) {}

    virtual ~Circle() {
        printf("Circle destroyed (r=%.2f)\n", radius_);
    }

    void draw() const override {
        printf("Drawing circle at (%.2f, %.2f) with radius %.2f\n", x_, y_, radius_);
    }

    double area() const override {
        return 3.14159265359 * radius_ * radius_;
    }

    const char* name() const override {
        return "Circle";
    }

    void scale(double factor) override {
        radius_ *= factor;
    }

    // Circle-specific method (not virtual in base)
    double circumference() const {
        return 2 * 3.14159265359 * radius_;
    }
};

// =============================================================================
// Concrete Class: Rectangle (inherits from IShape)
// =============================================================================
class Rectangle : public IShape {
protected:
    double width_, height_;
    double x_, y_;  // top-left corner

public:
    Rectangle(double w, double h, double x = 0, double y = 0)
        : width_(w), height_(h), x_(x), y_(y) {}

    virtual ~Rectangle() {
        printf("Rectangle destroyed (%.2fx%.2f)\n", width_, height_);
    }

    void draw() const override {
        printf("Drawing rectangle at (%.2f, %.2f) size %.2fx%.2f\n",
               x_, y_, width_, height_);
    }

    double area() const override {
        return width_ * height_;
    }

    const char* name() const override {
        return "Rectangle";
    }

    void scale(double factor) override {
        width_ *= factor;
        height_ *= factor;
    }

    double perimeter() const {
        return 2 * (width_ + height_);
    }
};

// =============================================================================
// Derived Class: Square (inherits from Rectangle)
// =============================================================================
class Square : public Rectangle {
public:
    Square(double side, double x = 0, double y = 0)
        : Rectangle(side, side, x, y) {}

    virtual ~Square() {
        printf("Square destroyed (side=%.2f)\n", width_);
    }

    const char* name() const override {
        return "Square";
    }

    // Override scale to maintain square aspect ratio
    void scale(double factor) override {
        width_ *= factor;
        height_ = width_;  // Keep it a square
    }
};

// =============================================================================
// Concrete Class: Triangle (inherits from IShape)
// =============================================================================
class Triangle : public IShape {
private:
    double base_, height_;
    double x_, y_;

public:
    Triangle(double b, double h, double x = 0, double y = 0)
        : base_(b), height_(h), x_(x), y_(y) {}

    virtual ~Triangle() {
        printf("Triangle destroyed (base=%.2f, height=%.2f)\n", base_, height_);
    }

    void draw() const override {
        printf("Drawing triangle at (%.2f, %.2f) base %.2f height %.2f\n",
               x_, y_, base_, height_);
    }

    double area() const override {
        return 0.5 * base_ * height_;
    }

    const char* name() const override {
        return "Triangle";
    }

    void scale(double factor) override {
        base_ *= factor;
        height_ *= factor;
    }
};

// =============================================================================
// Multiple Inheritance: SerializableCircle (IShape + ISerializable)
// =============================================================================
class SerializableCircle : public Circle, public ISerializable {
public:
    SerializableCircle(double r, double x = 0, double y = 0)
        : Circle(r, x, y) {}

    virtual ~SerializableCircle() {
        printf("SerializableCircle destroyed\n");
    }

    void serialize(char* buffer, size_t size) const override {
        snprintf(buffer, size, "SerializableCircle{area=%.2f}", area());
    }

    void deserialize(const char* buffer) override {
        // Simple stub - in real code would parse the buffer
        printf("Deserializing: %s\n", buffer);
    }
};

// =============================================================================
// Multiple Inheritance: SerializableRectangle (IShape + ISerializable)
// =============================================================================
class SerializableRectangle : public Rectangle, public ISerializable {
public:
    SerializableRectangle(double w, double h, double x = 0, double y = 0)
        : Rectangle(w, h, x, y) {}

    virtual ~SerializableRectangle() {
        printf("SerializableRectangle destroyed\n");
    }

    void serialize(char* buffer, size_t size) const override {
        snprintf(buffer, size, "SerializableRectangle{w=%.2f,h=%.2f}", width_, height_);
    }

    void deserialize(const char* buffer) override {
        printf("Deserializing: %s\n", buffer);
    }
};

// =============================================================================
// Deep Inheritance: ColoredSquare (extends Square with color)
// =============================================================================
class ColoredSquare : public Square {
private:
    unsigned int color_;  // RGB color

public:
    ColoredSquare(double side, unsigned int color, double x = 0, double y = 0)
        : Square(side, x, y), color_(color) {}

    virtual ~ColoredSquare() {
        printf("ColoredSquare destroyed (color=0x%06X)\n", color_);
    }

    void draw() const override {
        printf("Drawing colored square at (%.2f, %.2f) side %.2f color 0x%06X\n",
               x_, y_, width_, color_);
    }

    const char* name() const override {
        return "ColoredSquare";
    }

    virtual unsigned int getColor() const {
        return color_;
    }

    virtual void setColor(unsigned int c) {
        color_ = c;
    }
};

// =============================================================================
// Factory function to create shapes polymorphically
// =============================================================================
IShape* createShape(int type, double param1, double param2 = 0) {
    switch (type) {
        case 0: return new Circle(param1);
        case 1: return new Rectangle(param1, param2);
        case 2: return new Square(param1);
        case 3: return new Triangle(param1, param2);
        default: return nullptr;
    }
}

// =============================================================================
// Process shapes polymorphically
// =============================================================================
void processShapes(IShape** shapes, int count) {
    double totalArea = 0;

    printf("\n=== Processing %d shapes ===\n", count);
    for (int i = 0; i < count; i++) {
        if (shapes[i]) {
            printf("[%d] %s:\n", i, shapes[i]->name());
            shapes[i]->draw();
            double a = shapes[i]->area();
            printf("    Area: %.2f\n", a);
            totalArea += a;
        }
    }
    printf("Total area: %.2f\n", totalArea);
}

// =============================================================================
// Demo serialization with multiple inheritance
// =============================================================================
void demoSerialization() {
    printf("\n=== Serialization Demo ===\n");

    SerializableCircle sc(5.0, 1.0, 2.0);
    SerializableRectangle sr(4.0, 3.0, 0.0, 0.0);

    char buffer[256];

    // Use as IShape
    IShape* shape = &sc;
    shape->draw();

    // Use as ISerializable
    ISerializable* ser = &sc;
    ser->serialize(buffer, sizeof(buffer));
    printf("Serialized circle: %s\n", buffer);

    // Same for rectangle
    shape = &sr;
    shape->draw();

    ser = &sr;
    ser->serialize(buffer, sizeof(buffer));
    printf("Serialized rectangle: %s\n", buffer);
}

// =============================================================================
// Demo inheritance chain: Rectangle -> Square -> ColoredSquare
// =============================================================================
void demoInheritanceChain() {
    printf("\n=== Inheritance Chain Demo ===\n");

    Rectangle r(10, 5);
    Square s(7);
    ColoredSquare cs(4, 0xFF0000);  // Red square

    IShape* shapes[] = { &r, &s, &cs };

    for (int i = 0; i < 3; i++) {
        printf("%s area: %.2f\n", shapes[i]->name(), shapes[i]->area());
    }

    // Test virtual method resolution
    printf("\nScaling all by 2x:\n");
    for (int i = 0; i < 3; i++) {
        shapes[i]->scale(2.0);
        printf("%s new area: %.2f\n", shapes[i]->name(), shapes[i]->area());
    }
}

// =============================================================================
// Main entry point
// =============================================================================
int main(int argc, char* argv[]) {
    printf("Vtable Discovery Demo\n");
    printf("=====================\n");

    // Create various shapes
    IShape* shapes[6];
    shapes[0] = new Circle(3.0);
    shapes[1] = new Rectangle(4.0, 5.0);
    shapes[2] = new Square(6.0);
    shapes[3] = new Triangle(3.0, 4.0);
    shapes[4] = createShape(0, 2.5);  // Circle via factory
    shapes[5] = createShape(2, 8.0);  // Square via factory

    // Process all shapes polymorphically
    processShapes(shapes, 6);

    // Demo scaling
    printf("\n=== Scaling Demo ===\n");
    for (int i = 0; i < 6; i++) {
        if (shapes[i]) {
            shapes[i]->scale(1.5);
            printf("After scale 1.5x: %s area = %.2f\n",
                   shapes[i]->name(), shapes[i]->area());
        }
    }

    // Run other demos
    demoSerialization();
    demoInheritanceChain();

    // Cleanup - demonstrates virtual destructors
    printf("\n=== Cleanup (virtual destructors) ===\n");
    for (int i = 0; i < 6; i++) {
        delete shapes[i];
    }

    return 0;
}
