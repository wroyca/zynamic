/* SPDX-License-Identifier: GPL-3.0-only */

#include <zynamic/view/main_window.hpp>

#include <QLabel>

namespace Zynamic {
  
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
  ui->setupUi(this);
}

MainWindow::~MainWindow()
{
  delete ui;
}

} // namespace Zynamic
